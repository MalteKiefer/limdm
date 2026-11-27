package api

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// TypeLogging switches on log collection (docs/logs.md): the agent reads
// the systemd journal, container logs of Docker and Podman and plain files,
// filters and masks the lines on the device and ships them in batches over
// its mTLS connection. Off unless a declaration enables it; devices marked
// personal (tag "personal" or attribute ownership=personal) only collect
// with allow_personal.
const TypeLogging = "com.limdm.logging"

// LogPriorities are the syslog priorities, 0 (emerg) to 7 (debug).
var LogPriorities = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

// LogPriority is the number of a priority name, -1 for an unknown one.
func LogPriority(name string) int { return slices.Index(LogPriorities, strings.ToLower(name)) }

// Logging is the payload of com.limdm.logging. Empty limits use the
// defaults (LogDefaults): conservative, since a device also serves other
// work.
type Logging struct {
	Enabled       bool `json:"enabled"`
	AllowPersonal bool `json:"allow_personal,omitempty"` // also on devices marked personal (BYOD)
	// journald: units to include (empty: all) and exclude, * as wildcard
	Journald     bool     `json:"journald"`
	Units        []string `json:"units,omitempty"`
	ExcludeUnits []string `json:"exclude_units,omitempty"`
	MinPriority  string   `json:"min_priority,omitempty"` // emerg ... debug, default info
	// containers of Docker and Podman: by name (* as wildcard), label
	// (key=value) or compose project; without any include all of them
	Containers        bool     `json:"containers"`
	ContainerNames    []string `json:"container_names,omitempty"`
	ContainerLabels   []string `json:"container_labels,omitempty"`
	ComposeProjects   []string `json:"compose_projects,omitempty"`
	ExcludeContainers []string `json:"exclude_containers,omitempty"`
	// absolute paths of plain text log files, followed across rotation,
	// below /var/log/, /srv/<name>/log/ or one of Roots
	Files []string `json:"files,omitempty"`
	// Roots are further directories file sources may live in. The agent
	// reads them as root and ships them: saving an item with roots needs
	// four eyes approval when it is on (LogRootValid has the hard rules).
	Roots []string `json:"roots,omitempty"`
	// regular expressions on the message: with include only matching
	// lines are shipped, exclude drops matching lines
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	// masking: the built in rules (passwords, tokens, Authorization
	// headers, keys) unless mask_builtin is false, plus these expressions;
	// matched text becomes ***
	MaskBuiltin *bool    `json:"mask_builtin,omitempty"`
	Mask        []string `json:"mask,omitempty"`
	// limits per device; lines over them are dropped and counted
	LinesPerSecond int `json:"lines_per_second,omitempty"` // 1..1000, default 20
	MBPerDay       int `json:"mb_per_day,omitempty"`       // 1..10240, default 100
	BufferMB       int `json:"buffer_mb,omitempty"`        // spool for offline periods, 1..1024, default 32
}

// LogDefaults are the limits of empty fields.
const (
	LogDefaultLinesPerSecond = 20
	LogDefaultMBPerDay       = 100
	LogDefaultBufferMB       = 32
	LogDefaultPriority       = 6 // info
)

// Limits returns the effective rate, daily volume, buffer and priority.
func (l Logging) Limits() (linesPerSecond, mbPerDay, bufferMB, minPriority int) {
	linesPerSecond, mbPerDay, bufferMB, minPriority = l.LinesPerSecond, l.MBPerDay, l.BufferMB, LogPriority(l.MinPriority)
	if linesPerSecond <= 0 {
		linesPerSecond = LogDefaultLinesPerSecond
	}
	if mbPerDay <= 0 {
		mbPerDay = LogDefaultMBPerDay
	}
	if bufferMB <= 0 {
		bufferMB = LogDefaultBufferMB
	}
	if minPriority < 0 {
		minPriority = LogDefaultPriority
	}
	return
}

// MaskBuiltinOn reports whether the built in masking rules apply.
func (l Logging) MaskBuiltinOn() bool { return l.MaskBuiltin == nil || *l.MaskBuiltin }

var (
	logGlobRe  = regexp.MustCompile(`^[a-zA-Z0-9*][a-zA-Z0-9@._:*-]{0,127}$`)
	logLabelRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}=[^\x00-\x1f]{0,256}$`)
)

// Log files may only live below these roots (after symbolic links are
// resolved, on the agent): /var/log/ and /srv/<name>/log/. The agent reads
// them as root, so a path elsewhere, or a link planted in a log directory,
// must never reach other files. logSecretPrefixes are refused anywhere, as
// a second line.
var logSecretPrefixes = []string{"/etc/shadow", "/etc/gshadow", "/etc/ssh/", "/root/", "/etc/ssl/private/", "/var/lib/limdm/",
	"/etc/limdm/", "/proc/", "/sys/", "/dev/", "/run/", "/boot/"}

// logSecret reports a path in a secret location (or the location itself).
func logSecret(p string) bool {
	for _, s := range logSecretPrefixes {
		if p == strings.TrimSuffix(s, "/") || strings.HasPrefix(p, s) {
			return true
		}
	}
	parts := strings.Split(p, "/") // "", first, ...
	return len(parts) >= 3 && parts[1] == "home" && slices.Contains(parts[3:], ".ssh")
}

func cleanAbs(p string) bool {
	return strings.HasPrefix(p, "/") && p == path.Clean(p) && len(p) <= 512 && noControl(p, 512) && !strings.ContainsAny(p, "*?[")
}

// LogRootValid checks a custom root of file sources: a clean absolute
// directory at least two levels deep (never "/" or a bare top level
// directory such as /etc, /home or /opt), not in a secret location.
func LogRootValid(r string) bool {
	return cleanAbs(r) && strings.Count(r, "/") >= 2 && !logSecret(r)
}

// LogFileAllowed reports whether a clean absolute path is a permitted log
// file location: below /var/log/, /srv/<name>/log/ or one of roots (valid
// ones only), never in a secret location.
func LogFileAllowed(p string, roots []string) bool {
	if !cleanAbs(p) || logSecret(p) {
		return false
	}
	parts := strings.Split(p, "/")
	switch {
	case strings.HasPrefix(p, "/var/log/") && len(p) > len("/var/log/"):
		return true
	case len(parts) >= 5 && parts[1] == "srv" && parts[2] != "" && parts[3] == "log" && parts[4] != "":
		return true
	}
	return slices.ContainsFunc(roots, func(r string) bool { return LogRootValid(r) && strings.HasPrefix(p, r+"/") })
}

// LogGlob matches name against a pattern with * as the only wildcard.
func LogGlob(pattern, name string) bool {
	ok, err := path.Match(strings.ReplaceAll(pattern, "[", `\[`), name)
	return err == nil && ok
}

func (l Logging) validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if l.MinPriority != "" && LogPriority(l.MinPriority) < 0 {
		bad("min_priority must be one of %s", strings.Join(LogPriorities, ", "))
	}
	for _, f := range []struct {
		name string
		list []string
	}{{"units", l.Units}, {"exclude_units", l.ExcludeUnits}, {"container_names", l.ContainerNames}, {"exclude_containers", l.ExcludeContainers}, {"compose_projects", l.ComposeProjects}} {
		if len(f.list) > 100 {
			bad("%s: at most 100 entries", f.name)
		}
		for _, v := range f.list {
			if !logGlobRe.MatchString(v) {
				bad("%s: invalid name %q (letters, digits, @._:- and * as wildcard)", f.name, v)
			}
		}
	}
	if len(l.ContainerLabels) > 50 {
		bad("container_labels: at most 50 entries")
	}
	for _, v := range l.ContainerLabels {
		if !logLabelRe.MatchString(v) {
			bad("container_labels: %q must be key=value", v)
		}
	}
	if len(l.Files) > 50 {
		bad("files: at most 50 paths")
	}
	if len(l.Roots) > 20 {
		bad("roots: at most 20 directories")
	}
	for _, r := range l.Roots {
		if !LogRootValid(r) {
			bad("roots: %q must be a clean absolute directory at least two levels deep, outside secret locations", r)
		}
	}
	for _, f := range l.Files {
		if !cleanAbs(f) {
			bad("files: %q must be a clean absolute path without wildcards", f)
			continue
		}
		if !LogFileAllowed(f, l.Roots) {
			bad("files: %q must be below /var/log/, /srv/<name>/log/ or one of roots", f)
		}
	}
	for _, f := range []struct {
		name string
		list []string
	}{{"include", l.Include}, {"exclude", l.Exclude}, {"mask", l.Mask}} {
		if len(f.list) > 50 {
			bad("%s: at most 50 expressions", f.name)
		}
		for _, v := range f.list {
			if v == "" || len(v) > 512 {
				bad("%s: expressions of 1 to 512 characters", f.name)
			} else if _, err := regexp.Compile(v); err != nil {
				bad("%s: %v", f.name, err)
			}
		}
	}
	if l.LinesPerSecond < 0 || l.LinesPerSecond > 1000 {
		bad("lines_per_second must be 1..1000 (0 for %d)", LogDefaultLinesPerSecond)
	}
	if l.MBPerDay < 0 || l.MBPerDay > 10240 {
		bad("mb_per_day must be 1..10240 (0 for %d)", LogDefaultMBPerDay)
	}
	if l.BufferMB < 0 || l.BufferMB > 1024 {
		bad("buffer_mb must be 1..1024 (0 for %d)", LogDefaultBufferMB)
	}
	if l.Enabled && !l.Journald && !l.Containers && len(l.Files) == 0 {
		bad("enabled needs at least one source: journald, containers or files")
	}
	return errors.Join(errs...)
}

// applyLogging decodes and validates the logging type.
func (d Declaration) applyLogging(p *Policy) (bool, error) {
	if d.Type != TypeLogging {
		return false, nil
	}
	var v Logging
	if err := strict(d.Payload, &v); err != nil {
		return true, err
	}
	p.Extra.Logging = &v
	return true, v.validate()
}

func init() {
	Types[TypeLogging] = `{"enabled": true, "journald": true, "exclude_units": ["systemd-logind.service"], "min_priority": "info", "containers": true, "exclude_containers": ["*-tmp"], "files": ["/var/log/nginx/error.log"], "exclude": ["healthcheck"], "mask": ["customer-[0-9]+"], "lines_per_second": 20, "mb_per_day": 100, "buffer_mb": 32}`
	payloadShapes[TypeLogging] = Logging{}
}

// Log sources of LogLine.Source.
const (
	LogSourceJournald  = "journald"
	LogSourceContainer = "container"
	LogSourceFile      = "file"
)

// LogLine is one log line as the agent ships it. Cursor identifies the
// line at its source (journal cursor, container and time, file inode and
// offset); the server drops a line it already has for the same device,
// source and cursor, so a batch sent twice is stored once.
type LogLine struct {
	Time     time.Time         `json:"t"`
	Source   string            `json:"s"`
	Unit     string            `json:"u,omitempty"` // unit, container name or file path
	Priority int               `json:"p"`
	Host     string            `json:"h,omitempty"`
	Message  string            `json:"m"`
	Fields   map[string]string `json:"f,omitempty"`
	Cursor   string            `json:"c"`
}

// LogBatch is the body of POST /api/v1/logs (gzip encoded).
type LogBatch struct {
	Lines   []LogLine `json:"lines"`
	Dropped int64     `json:"dropped,omitempty"` // lines dropped on the device since the last batch (rate, volume, full buffer)
}

// LogBatchResult answers a batch.
type LogBatchResult struct {
	Stored     int `json:"stored"`
	Duplicates int `json:"duplicates"`
	Skipped    int `json:"skipped"` // outside the server's retention window
}

// Batch limits the server enforces.
const (
	LogBatchLines   = 2000
	LogBatchBytes   = 4 << 20 // decompressed
	LogMessageBytes = 8 << 10
)
