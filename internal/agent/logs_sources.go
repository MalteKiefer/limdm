package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Log sources: the journal through journalctl, containers through the
// docker or podman CLI (the same tools the workload inventory uses), files
// by inode and offset. Each read is bounded in time and output.

// capBuffer keeps the first max bytes written to it.
type capBuffer struct {
	bytes.Buffer
	max int
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// runLogCmd runs a tool and returns at most max bytes of its output; it
// stops the tool once that much is read (the caller uses complete lines).
var runLogCmd = func(name string, args []string, max int) (stdout, stderr []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.WaitDelay = 5 * time.Second
	errb := &capBuffer{max: max}
	cmd.Stderr = errb
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	out, _ := io.ReadAll(io.LimitReader(pipe, int64(max)))
	full := len(out) >= max
	if full {
		cancel()
	}
	werr := cmd.Wait()
	if werr != nil && !full {
		return out, errb.Bytes(), fmt.Errorf("%s: %w: %s", name, werr, lastLines(errb.String(), 2))
	}
	return out, errb.Bytes(), nil
}

// ---- journald ----

// readJournal reads the entries after cursor (at least priority prio,
// only the given units when any). Without a cursor it returns the cursor of
// the newest entry: collection starts now, not with the whole journal.
func readJournal(cursor string, units []string, prio int) ([]api.LogLine, string, error) {
	if cursor == "" {
		out, _, err := runLogCmd("journalctl", []string{"-o", "json", "-n", "1", "--no-pager"}, 1<<20)
		if err != nil {
			return nil, "", err
		}
		_, cur := parseJournal(out)
		return nil, cur, nil
	}
	args := []string{"-o", "json", "--no-pager", "--after-cursor=" + cursor, "-p", strconv.Itoa(prio)}
	for _, u := range units {
		args = append(args, "-u", u)
	}
	out, _, err := runLogCmd("journalctl", args, 8<<20)
	if err != nil {
		return nil, "", err // a cursor the journal no longer has: restart at the end
	}
	lines, cur := parseJournal(out)
	if cur == "" {
		cur = cursor
	}
	return lines, cur, nil
}

// journalFields are the journal fields kept with a line.
var journalFields = []string{"SYSLOG_IDENTIFIER", "_PID", "_COMM", "_TRANSPORT", "CONTAINER_NAME"}

// parseJournal reads journalctl -o json output: complete lines only, at
// most logPassMax, and the cursor of the last one read.
func parseJournal(out []byte) ([]api.LogLine, string) {
	var lines []api.LogLine
	cursor := ""
	for len(out) > 0 && len(lines) < logPassMax {
		i := bytes.IndexByte(out, '\n')
		if i < 0 {
			break // cut off by the output limit
		}
		raw := out[:i]
		out = out[i+1:]
		var e map[string]json.RawMessage
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		str := func(k string) string {
			var s string
			if json.Unmarshal(e[k], &s) == nil {
				return s
			}
			var b []byte // binary values come as an array of byte values
			var nums []int
			if json.Unmarshal(e[k], &nums) == nil {
				for _, n := range nums {
					b = append(b, byte(n)) //nolint:gosec // journal byte values, 0 to 255
				}
			}
			return strings.ToValidUTF8(string(b), "?")
		}
		cur := str("__CURSOR")
		if cur == "" {
			continue
		}
		cursor = cur
		us, _ := strconv.ParseInt(str("__REALTIME_TIMESTAMP"), 10, 64)
		p, err := strconv.Atoi(str("PRIORITY"))
		if err != nil || p < 0 || p > 7 {
			p = 6
		}
		l := api.LogLine{Time: time.UnixMicro(us).UTC(), Source: api.LogSourceJournald, Unit: cmpOr(str("_SYSTEMD_UNIT"), str("SYSLOG_IDENTIFIER")),
			Priority: p, Host: str("_HOSTNAME"), Message: str("MESSAGE"), Cursor: cur, Fields: map[string]string{}}
		for _, f := range journalFields {
			if v := str(f); v != "" {
				l.Fields[f] = truncate(v, 256)
			}
		}
		lines = append(lines, l)
	}
	return lines, cursor
}

// guessPriority reads a level from the text of a container or file line;
// def when it names none.
func guessPriority(msg string, def int) int {
	head := strings.ToLower(truncate(msg, 120))
	for _, k := range []struct {
		word string
		p    int
	}{{"panic", 2}, {"fatal", 2}, {"crit", 2}, {"error", 3}, {"err ", 3}, {"warn", 4}} {
		if strings.Contains(head, k.word) {
			return min(k.p, def)
		}
	}
	return def
}

// ---- containers ----

// logToolPresent reports whether docker or podman can be asked.
var logToolPresent = func(kind string) bool { return workloadPresent(kind) }

// logContainer is a running container as the log filter sees it.
type logContainer struct {
	ID, Name, Image, Project string
	Labels                   map[string]string
}

func listContainers(kind string) ([]logContainer, error) {
	ids, _, err := runLogCmd(kind, []string{"ps", "--quiet", "--no-trunc"}, 1<<20)
	if err != nil {
		return nil, err
	}
	list := slices.DeleteFunc(strings.Fields(string(ids)), func(id string) bool { return !api.ValidWorkloadID(kind, id) })
	if len(list) == 0 {
		return nil, nil
	}
	out, _, err := runLogCmd(kind, append([]string{"container", "inspect"}, list...), 16<<20)
	if err != nil {
		return nil, err
	}
	var raw []ociInspect
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	var cs []logContainer
	for _, r := range raw {
		l := r.Config.Labels
		cs = append(cs, logContainer{ID: r.ID, Name: strings.TrimPrefix(r.Name, "/"), Image: cmpOr(r.ImageName, r.Config.Image), Labels: l,
			Project: cmpOr(l["com.docker.compose.project"], l["io.podman.compose.project"])})
	}
	return cs, nil
}

// wanted applies the container filters of the declaration.
func wantedContainer(cfg api.Logging, ct logContainer) bool {
	if matchAny(cfg.ExcludeContainers, ct.Name) {
		return false
	}
	if len(cfg.ContainerNames) == 0 && len(cfg.ContainerLabels) == 0 && len(cfg.ComposeProjects) == 0 {
		return true
	}
	if matchAny(cfg.ContainerNames, ct.Name) || ct.Project != "" && matchAny(cfg.ComposeProjects, ct.Project) {
		return true
	}
	return slices.ContainsFunc(cfg.ContainerLabels, func(kv string) bool {
		k, v, _ := strings.Cut(kv, "=")
		got, ok := ct.Labels[k]
		return ok && got == v
	})
}

func (c *logCollector) collectContainers() {
	if c.st.Containers == nil {
		c.st.Containers = map[string]time.Time{}
	}
	seen := map[string]bool{}
	for _, kind := range []string{"docker", "podman"} {
		if !logToolPresent(kind) {
			continue
		}
		list, err := listContainers(kind)
		if err != nil {
			for k := range c.st.Containers { // keep the cursors through a failed listing
				seen[k] = true
			}
			continue
		}
		for _, ct := range list {
			if !wantedContainer(c.cfg, ct) {
				continue
			}
			key := kind + ":" + ct.ID
			seen[key] = true
			since, ok := c.st.Containers[key]
			if !ok {
				c.st.Containers[key] = c.now().UTC() // new: from now on
				continue
			}
			lines, last, err := containerLogs(kind, ct, since)
			if err == nil && c.add(lines) == nil && last.After(since) {
				c.st.Containers[key] = last
			}
		}
	}
	for k := range c.st.Containers {
		if !seen[k] {
			delete(c.st.Containers, k)
		}
	}
}

// containerLogs reads the lines of a container after since: standard
// output as info, standard error as notice (raised by keywords), sorted by
// time and cut at logPassMax.
func containerLogs(kind string, ct logContainer, since time.Time) ([]api.LogLine, time.Time, error) {
	stdout, stderr, err := runLogCmd(kind, []string{"logs", "--timestamps", "--since", since.Format(time.RFC3339Nano), ct.ID}, 4<<20)
	if err != nil {
		return nil, since, err
	}
	short := ct.ID[:min(12, len(ct.ID))]
	fields := map[string]string{"container_id": short}
	if ct.Image != "" {
		fields["image"] = truncate(ct.Image, 256)
	}
	if ct.Project != "" {
		fields["compose_project"] = ct.Project
	}
	var lines []api.LogLine
	for _, s := range []struct {
		out  []byte
		prio int
	}{{stdout, 6}, {stderr, 5}} {
		for _, raw := range strings.Split(string(s.out), "\n") {
			ts, msg, ok := strings.Cut(strings.TrimRight(raw, "\r"), " ")
			t, err := time.Parse(time.RFC3339Nano, ts)
			if !ok || err != nil || !t.After(since) {
				continue
			}
			h := fnv.New64a()
			h.Write([]byte(msg))
			f := make(map[string]string, len(fields))
			for k, v := range fields {
				f[k] = v
			}
			lines = append(lines, api.LogLine{Time: t.UTC(), Source: api.LogSourceContainer, Unit: ct.Name, Priority: guessPriority(msg, s.prio),
				Message: strings.ToValidUTF8(msg, "?"), Fields: f, Cursor: fmt.Sprintf("%s:%s:%d:%x", kind, short, t.UnixNano(), h.Sum64())})
		}
	}
	slices.SortStableFunc(lines, func(a, b api.LogLine) int { return a.Time.Compare(b.Time) })
	if len(lines) > logPassMax {
		lines = lines[:logPassMax]
	}
	last := since
	if len(lines) > 0 {
		last = lines[len(lines)-1].Time
	}
	return lines, last, nil
}

// ---- files ----

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

func (c *logCollector) collectFiles() {
	if c.st.Files == nil {
		c.st.Files = map[string]fileCursor{}
	}
	for p := range c.st.Files {
		if !slices.Contains(c.cfg.Files, p) {
			delete(c.st.Files, p)
		}
	}
	for _, p := range c.cfg.Files {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		ino := inode(fi)
		cur, ok := c.st.Files[p]
		if !ok {
			c.st.Files[p] = fileCursor{ino, fi.Size()} // new: from the current end on
			continue
		}
		if cur.Inode != ino {
			// rotated: read the rest of the old file when it was renamed to .1
			if old, err := os.Stat(p + ".1"); err == nil && inode(old) == cur.Inode {
				if lines, _, err := readFileFrom(p+".1", p, cur, true); err == nil {
					_ = c.add(lines)
				}
			}
			cur = fileCursor{Inode: ino}
		} else if fi.Size() < cur.Offset {
			cur.Offset = 0 // truncated in place (copytruncate)
		}
		lines, off, err := readFileFrom(p, p, cur, false)
		if err == nil && c.add(lines) == nil {
			c.st.Files[p] = fileCursor{ino, off}
		}
	}
}

// readFileFrom reads complete lines from offset (at most 4 MiB and
// logPassMax lines); with final the last line counts without a newline.
func readFileFrom(path, unit string, cur fileCursor, final bool) ([]api.LogLine, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, cur.Offset, err
	}
	defer f.Close()
	if _, err := f.Seek(cur.Offset, io.SeekStart); err != nil {
		return nil, cur.Offset, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return nil, cur.Offset, err
	}
	var lines []api.LogLine
	off, now := cur.Offset, time.Now().UTC()
	for len(b) > 0 && len(lines) < logPassMax {
		i := bytes.IndexByte(b, '\n')
		if i < 0 && !final {
			break // the writer is not done with this line
		}
		if i < 0 {
			i = len(b)
		}
		msg := strings.TrimRight(string(b[:i]), "\r")
		if msg != "" {
			lines = append(lines, api.LogLine{Time: now, Source: api.LogSourceFile, Unit: unit, Priority: guessPriority(msg, 6),
				Message: strings.ToValidUTF8(msg, "?"), Cursor: fmt.Sprintf("%d:%d", cur.Inode, off)})
		}
		off += int64(min(i+1, len(b)))
		b = b[min(i+1, len(b)):]
	}
	return lines, off, nil
}
