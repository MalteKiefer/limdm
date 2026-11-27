package agent

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Log collection (com.limdm.logging, docs/logs.md). Every logEvery the
// agent reads what is new in the journal, the container logs and the
// declared files, filters, masks and rate limits the lines and appends them
// to a spool on disk. The spool is shipped segment by segment over the mTLS
// connection; a segment is removed once the server stored it, so a batch
// lost on the way is sent again (the server drops duplicates by cursor).
// The spool is bounded: when full, the oldest segment goes and its lines
// are counted as dropped. Source cursors advance when lines reach the
// spool. The agent never reconfigures or restarts journald or Docker.

// logDir holds the spool and the cursors (a variable for tests).
var logDir = stateDir + "/logs"

const (
	logEvery       = 30 * time.Second
	logSegmentSize = 256 << 10 // a segment is one batch
	logSegmentMax  = 1000      // lines per segment
	logPassMax     = 5000      // lines read per source and pass
)

// logState is what survives a restart: cursors, the volume of the day and
// lines dropped since the last batch.
type logState struct {
	Journal    string                `json:"journal,omitempty"`
	Containers map[string]time.Time  `json:"containers,omitempty"` // container ID: time of the last line
	Files      map[string]fileCursor `json:"files,omitempty"`
	Day        string                `json:"day,omitempty"`
	DayBytes   int64                 `json:"day_bytes,omitempty"`
	Dropped    int64                 `json:"dropped,omitempty"`
}

type fileCursor struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// logCollector filters and spools lines for one configuration.
type logCollector struct {
	dir     string
	cfg     api.Logging
	cfgKey  string
	include []*regexp.Regexp
	exclude []*regexp.Regexp
	mask    []maskRule
	st      logState
	tokens  float64
	refill  time.Time
	seg     *os.File // open spool segment
	segN    int
	segSize int64
	now     func() time.Time
}

type maskRule struct {
	re   *regexp.Regexp
	repl string
}

// builtinMasks hide credentials that commonly end up in logs.
var builtinMasks = []maskRule{
	{regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)((?:bearer|basic|negotiate|token|digest)\s+)?[^\s,;"']+`), "${1}${2}***"},
	{regexp.MustCompile(`(?i)((?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']?)[^\s"',;&]+`), "${1}***"},
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), "***"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), "***"}, // JWT
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), "***"},                                // AWS access key ID
	{regexp.MustCompile(`(://[^/\s:@]+:)[^/\s@]+@`), "${1}***@"},                                // credentials in URLs
}

func newLogCollector(dir string) *logCollector {
	c := &logCollector{dir: dir, now: time.Now}
	if b, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		_ = json.Unmarshal(b, &c.st)
	}
	return c
}

// configure compiles a new configuration; the cursors stay.
func (c *logCollector) configure(cfg api.Logging) error {
	key, _ := json.Marshal(cfg)
	if string(key) == c.cfgKey {
		return nil
	}
	comp := func(list []string) ([]*regexp.Regexp, error) {
		var out []*regexp.Regexp
		for _, s := range list {
			re, err := regexp.Compile(s)
			if err != nil {
				return nil, err
			}
			out = append(out, re)
		}
		return out, nil
	}
	inc, err := comp(cfg.Include)
	if err != nil {
		return err
	}
	exc, err := comp(cfg.Exclude)
	if err != nil {
		return err
	}
	custom, err := comp(cfg.Mask)
	if err != nil {
		return err
	}
	var mask []maskRule
	if cfg.MaskBuiltinOn() {
		mask = append(mask, builtinMasks...)
	}
	for _, re := range custom {
		mask = append(mask, maskRule{re, "***"})
	}
	c.cfg, c.cfgKey, c.include, c.exclude, c.mask = cfg, string(key), inc, exc, mask
	return nil
}

// maskText applies the masking rules.
func (c *logCollector) maskText(s string) string {
	for _, m := range c.mask {
		s = m.re.ReplaceAllString(s, m.repl)
	}
	return s
}

// keep filters, masks and rate limits one line; false drops it (counted
// when a limit dropped it).
func (c *logCollector) keep(l *api.LogLine) bool {
	if _, _, _, prio := c.cfg.Limits(); l.Priority > prio {
		return false
	}
	if len(c.include) > 0 && !slices.ContainsFunc(c.include, func(re *regexp.Regexp) bool { return re.MatchString(l.Message) }) {
		return false
	}
	if slices.ContainsFunc(c.exclude, func(re *regexp.Regexp) bool { return re.MatchString(l.Message) }) {
		return false
	}
	rate, mb, _, _ := c.cfg.Limits()
	now := c.now()
	if day := now.UTC().Format(time.DateOnly); day != c.st.Day {
		c.st.Day, c.st.DayBytes = day, 0
	}
	if !c.refill.IsZero() {
		c.tokens += now.Sub(c.refill).Seconds() * float64(rate)
	} else {
		c.tokens = float64(rate) * 10
	}
	c.tokens, c.refill = min(c.tokens, float64(rate)*10), now // bursts of ten seconds
	size := int64(len(l.Message) + len(l.Unit))
	for k, v := range l.Fields {
		size += int64(len(k) + len(v))
	}
	if c.tokens < 1 || c.st.DayBytes+size > int64(mb)<<20 {
		c.st.Dropped++
		return false
	}
	c.tokens--
	c.st.DayBytes += size
	if len(l.Message) > api.LogMessageBytes {
		l.Message = truncate(l.Message, api.LogMessageBytes)
	}
	l.Message = c.maskText(l.Message)
	for k, v := range l.Fields {
		l.Fields[k] = c.maskText(v)
	}
	return true
}

// add filters lines into the spool.
func (c *logCollector) add(lines []api.LogLine) error {
	for i := range lines {
		if !c.keep(&lines[i]) {
			continue
		}
		if err := c.append(lines[i]); err != nil {
			return err
		}
	}
	return nil
}

// segments lists the closed spool segments, oldest first, with their lines.
func (c *logCollector) segments() ([]string, error) {
	list, err := filepath.Glob(filepath.Join(c.dir, "seg-*.ndjson"))
	slices.Sort(list) // names start with a fixed width time
	return list, err
}

// segLines reads the line count from a closed segment's name.
func segLines(name string) int64 {
	base := strings.TrimSuffix(filepath.Base(name), ".ndjson")
	n, _ := strconv.ParseInt(base[strings.LastIndexByte(base, '-')+1:], 10, 64)
	return n
}

// open opens the segment lines are appended to.
func (c *logCollector) open() error {
	if c.seg != nil {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(c.dir, "open.ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	c.seg, c.segSize, c.segN = f, fi.Size(), 0
	if fi.Size() > 0 { // left by a restart: count its lines
		b, _ := os.ReadFile(f.Name())
		c.segN = bytes.Count(b, []byte("\n"))
	}
	return nil
}

func (c *logCollector) append(l api.LogLine) error {
	if err := c.open(); err != nil {
		return err
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := c.seg.Write(b); err != nil {
		return err
	}
	c.segSize += int64(len(b))
	c.segN++
	if c.segSize >= logSegmentSize || c.segN >= logSegmentMax {
		return c.closeSegment()
	}
	return nil
}

// closeSegment turns the open segment into a closed one and bounds the spool.
func (c *logCollector) closeSegment() error {
	if c.seg == nil {
		if fi, err := os.Stat(filepath.Join(c.dir, "open.ndjson")); err != nil || fi.Size() == 0 {
			return nil
		}
		if err := c.open(); err != nil { // left by a restart
			return err
		}
	}
	if err := c.seg.Sync(); err != nil {
		return err
	}
	c.seg.Close()
	name := filepath.Join(c.dir, fmt.Sprintf("seg-%020d-%d.ndjson", c.now().UnixNano(), c.segN))
	c.seg = nil
	if err := os.Rename(filepath.Join(c.dir, "open.ndjson"), name); err != nil {
		return err
	}
	return c.bound()
}

// bound drops the oldest segments while the spool exceeds the buffer size.
func (c *logCollector) bound() error {
	_, _, bufMB, _ := c.cfg.Limits()
	list, err := c.segments()
	if err != nil {
		return err
	}
	var total int64
	sizes := make([]int64, len(list))
	for i, f := range list {
		if fi, err := os.Stat(f); err == nil {
			sizes[i] = fi.Size()
			total += fi.Size()
		}
	}
	for i := 0; i < len(list) && total > int64(bufMB)<<20; i++ {
		if err := os.Remove(list[i]); err != nil {
			return err
		}
		total -= sizes[i]
		c.st.Dropped += segLines(list[i])
	}
	return nil
}

func (c *logCollector) save() error {
	b, _ := json.Marshal(c.st)
	tmp := filepath.Join(c.dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.dir, "state.json"))
}

// reset forgets spool and cursors: collection was switched off.
func (c *logCollector) reset() {
	if c.seg != nil {
		c.seg.Close()
		c.seg = nil
	}
	if c.cfgKey == "" && c.st.Day == "" {
		return
	}
	_ = os.RemoveAll(c.dir)
	*c = logCollector{dir: c.dir, now: c.now}
}

// errLogBusy carries the server's Retry-After.
type errLogBusy struct{ after time.Duration }

func (e errLogBusy) Error() string { return "log store busy, retry in " + e.after.String() }

// ship sends closed segments, oldest first, until one fails.
func (c *logCollector) ship(ctx context.Context, send func(context.Context, api.LogBatch) error) error {
	if err := c.closeSegment(); err != nil {
		return err
	}
	list, err := c.segments()
	if err != nil {
		return err
	}
	for _, f := range list {
		lines, err := readSegment(f)
		if err != nil {
			_ = os.Remove(f) // unreadable: dropped, counted
			c.st.Dropped += segLines(f)
			continue
		}
		batch := api.LogBatch{Lines: lines, Dropped: c.st.Dropped}
		if err := send(ctx, batch); err != nil {
			return err
		}
		c.st.Dropped -= batch.Dropped
		if err := os.Remove(f); err != nil {
			return err
		}
		if err := c.save(); err != nil {
			return err
		}
	}
	return nil
}

func readSegment(name string) ([]api.LogLine, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []api.LogLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var l api.LogLine
		if json.Unmarshal(sc.Bytes(), &l) == nil && l.Cursor != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// postLogs sends one batch gzip compressed.
func (a *Agent) postLogs(ctx context.Context, b api.LogBatch) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Server+"/api/v1/logs", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		after, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		return errLogBusy{time.Duration(min(max(after, 30), 3600)) * time.Second}
	}
	return apiError("/api/v1/logs", resp)
}

// logLoop collects and ships logs while a declaration enables it.
func (a *Agent) logLoop(ctx context.Context) {
	c := newLogCollector(logDir)
	wait, failures := logEvery, 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = logEvery
		cfg := a.policy().Extra.Logging
		if cfg == nil || !cfg.Enabled {
			c.reset()
			continue
		}
		if err := os.MkdirAll(c.dir, 0o700); err != nil {
			a.log.Warn("log collection", "err", err)
			continue
		}
		if err := c.configure(*cfg); err != nil {
			a.log.Warn("log collection", "err", err)
			continue
		}
		c.collect()
		if err := c.save(); err != nil {
			a.log.Warn("log collection state", "err", err)
		}
		sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := c.ship(sctx, a.postLogs)
		cancel()
		var busy errLogBusy
		switch {
		case errors.As(err, &busy):
			wait = busy.after
		case err != nil:
			failures++
			wait = min(logEvery<<min(failures, 4), 10*time.Minute)
			if failures == 3 {
				a.log.Warn("log shipping failing", "err", err) // not per attempt: no loop of own lines
			}
		default:
			failures = 0
		}
	}
}

// collect reads every enabled source once.
func (c *logCollector) collect() {
	_, _, _, prio := c.cfg.Limits()
	if c.cfg.Journald {
		lines, cur, err := readJournal(c.st.Journal, c.cfg.Units, prio)
		if err == nil {
			lines = slices.DeleteFunc(lines, func(l api.LogLine) bool { return ownLine(l) || matchAny(c.cfg.ExcludeUnits, l.Unit) })
			if c.add(lines) == nil {
				c.st.Journal = cur
			}
		}
	}
	if c.cfg.Containers {
		c.collectContainers()
	}
	if len(c.cfg.Files) > 0 {
		c.collectFiles()
	}
}

// ownLine reports lines of LiMDM itself, which are never shipped: the
// agent must not ship the lines its own shipping writes.
func ownLine(l api.LogLine) bool {
	return strings.HasPrefix(l.Unit, "limdm") || l.Fields["SYSLOG_IDENTIFIER"] == "limdm-agent" || strings.HasPrefix(l.Unit, "/var/log/limdm")
}

func matchAny(patterns []string, name string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return api.LogGlob(p, name) })
}
