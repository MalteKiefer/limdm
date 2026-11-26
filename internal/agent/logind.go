package agent

import (
	"strconv"
	"strings"
)

// sessionsDir holds logind's session records (systemd and elogind).
var sessionsDir = "/run/systemd/sessions"

// logindSession returns the record logind keeps for the session scope a
// /proc/<pid>/cgroup text names (keys REMOTE, SEAT, TYPE, SERVICE, ...);
// nil when the process runs outside a session scope. Processes started by
// the user's systemd manager (user@.service) belong to no session.
func logindSession(cgroup string) map[string]string {
	for _, l := range strings.Split(cgroup, "\n") {
		i := strings.LastIndex(l, "/session-")
		if i < 0 || !strings.HasSuffix(l, ".scope") {
			continue
		}
		id := strings.TrimSuffix(l[i+len("/session-"):], ".scope")
		if !sessionIDRe.MatchString(id) {
			continue
		}
		rec := map[string]string{}
		for _, kv := range strings.Split(readFile(sessionsDir+"/"+id), "\n") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				rec[k] = v
			}
		}
		if len(rec) > 0 {
			return rec
		}
	}
	return nil
}

// remoteCgroup reports whether a process cgroup is a remote logind session
// or lies below the SSH daemon (sshd without pam_systemd).
func remoteCgroup(cgroup string) bool {
	for _, svc := range []string{"/ssh.service", "/sshd.service", "/sshd@", "/ssh@"} {
		if strings.Contains(cgroup, svc) {
			return true
		}
	}
	s := logindSession(cgroup)
	return s != nil && s["REMOTE"] == "1"
}

// remoteProcess is remoteCgroup for a running process.
func remoteProcess(pid int32) bool {
	return remoteCgroup(readFile("/proc/" + strconv.Itoa(int(pid)) + "/cgroup"))
}
