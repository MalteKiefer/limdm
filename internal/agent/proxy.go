package agent

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"github.com/maltekiefer/limdm/internal/api"
)

const (
	proxyProfile = "/etc/profile.d/limdm-proxy.sh"
	proxyEnvD    = "/etc/environment.d/60-limdm-proxy.conf"
	proxyUnit    = "/etc/systemd/system/limdm-agent.service.d/60-limdm-proxy.conf"
	proxyApt     = "/etc/apt/apt.conf.d/60limdm-proxy"
	proxyDnf5    = "/etc/dnf/libdnf5.conf.d/60-limdm-proxy.conf"
	dnfConf      = "/etc/dnf/dnf.conf" // dnf4 (RHEL 9 family) has no drop in directory for [main]
)

// declaredProxy is the proxy the agent's own HTTP clients use. Nil until a
// proxy declaration was applied or removed in this process: then the
// environment of the unit (our drop in) decides, as read at start.
var declaredProxy atomic.Pointer[api.Proxy]

// agentProxy picks the proxy for the agent's requests. It is evaluated per
// request, so a new or removed declaration applies without a restart
// (http.ProxyFromEnvironment reads the environment only once).
func agentProxy(r *http.Request) (*url.URL, error) {
	p := declaredProxy.Load()
	if p == nil {
		return http.ProxyFromEnvironment(r)
	}
	host := r.URL.Hostname()
	if host == "localhost" || noProxyMatch(host, p.NoProxy) {
		return nil, nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil, nil
	}
	u := p.HTTP
	if r.URL.Scheme == "https" {
		u = p.HTTPS
	}
	if u == "" {
		return nil, nil
	}
	return url.Parse(u)
}

// noProxyMatch reports whether host is excluded by a no_proxy list: "*",
// exact names, domain suffixes (".example.com" or "example.com"), addresses
// and CIDR ranges. Ports in entries are ignored.
func noProxyMatch(host, list string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	ip := net.ParseIP(h)
	for _, e := range strings.Split(strings.ToLower(list), ",") {
		e = strings.TrimSpace(e)
		switch {
		case e == "":
			continue
		case e == "*":
			return true
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			if ip != nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if eh, _, err := net.SplitHostPort(e); err == nil {
			e = eh
		}
		e = strings.Trim(strings.TrimPrefix(e, "*"), ".[]")
		if h == e || (ip == nil && strings.HasSuffix(h, "."+e)) {
			return true
		}
	}
	return false
}

// proxyVars are the variables a proxy declaration sets, lower and upper case.
func proxyVars(p *api.Proxy) map[string]string {
	m := map[string]string{}
	for k, v := range map[string]string{"http_proxy": p.HTTP, "https_proxy": p.HTTPS, "no_proxy": p.NoProxy} {
		if v != "" {
			m[k], m[strings.ToUpper(k)] = v, v
		}
	}
	return m
}

// applyProxy writes the proxy for login shells, user sessions, apt, dnf4 and
// dnf5, and the agent's own unit; it sets the variables in the agent's
// environment too, so pacman, apk, flatpak and every other tool the agent
// runs inherit them right away. Removing the declaration cleans all up.
func (a *Agent) applyProxy(p *api.Proxy) error {
	var profile, envd, unit, apt, dnf, dnfProxy string
	vars := map[string]string{}
	if p != nil {
		vars = proxyVars(p)
		var b, e, u strings.Builder
		b.WriteString(managedHeader)
		e.WriteString(managedHeader)
		u.WriteString(managedHeader + "[Service]\n")
		for _, k := range sortedKeys(vars) {
			v := vars[k]
			fmt.Fprintf(&b, "export %s='%s'\n", k, strings.ReplaceAll(v, "'", `'\''`)) // single quotes: no shell expansion
			fmt.Fprintf(&e, "%s=%s\n", k, v)
			fmt.Fprintf(&u, "Environment=%s=%s\n", k, v) // values are allowlisted: no spaces, quotes or % specifiers
		}
		profile, envd, unit = b.String(), e.String(), u.String()
		if p.HTTP != "" || p.HTTPS != "" {
			apt = managedHeader
			if p.HTTP != "" {
				apt += fmt.Sprintf("Acquire::http::Proxy %q;\n", p.HTTP)
			}
			if p.HTTPS != "" {
				apt += fmt.Sprintf("Acquire::https::Proxy %q;\n", p.HTTPS)
			}
		}
		if dnfProxy = firstNonEmpty(p.HTTPS, p.HTTP); dnfProxy != "" {
			dnf = managedHeader + "[main]\nproxy=" + dnfProxy + "\n"
		}
	}
	_, e1 := writeOrRemove(proxyProfile, profile, 0o644)
	_, e2 := writeOrRemove(proxyEnvD, envd, 0o644)
	var e3 error
	switch a.host.family {
	case "debian":
		_, e3 = writeOrRemove(proxyApt, apt, 0o644)
	case "fedora":
		_, e3 = writeOrRemove(proxyDnf5, dnf, 0o644)
		if exists(dnfConf) {
			var prev string
			prev, e3 = syncINIKey(dnfConf, "main", "proxy", dnfProxy, a.state.DNFProxy)
			if e3 == nil {
				a.state.DNFProxy = prev
			}
		}
	}
	var e4 error
	unitRemoved := false
	if systemd() {
		changed, err := writeOrRemove(proxyUnit, unit, 0o644)
		e4, unitRemoved = err, changed && unit == ""
		if changed && err == nil {
			_, e4 = sh("systemctl", "daemon-reload") // the next start of the agent has the variables
		}
	}
	// the agent's own environment and HTTP clients, without a restart
	if p != nil || a.proxySet || unitRemoved {
		a.proxySet = p != nil
		for _, k := range []string{"http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} {
			if v, ok := vars[k]; ok {
				os.Setenv(k, v) //nolint:errcheck // valid names, cannot fail
			} else {
				os.Unsetenv(k) //nolint:errcheck // valid names, cannot fail
			}
		}
		q := api.Proxy{}
		if p != nil {
			q = *p
		}
		declaredProxy.Store(&q)
	}
	return errors.Join(e1, e2, e3, e4)
}

// syncINIKey sets key in section of an INI style file (dnf.conf, pacman.conf), or
// removes it when want is empty and the value is still the one LiMDM wrote
// (prev). It returns the value LiMDM now owns.
func syncINIKey(path, section, key, want, prev string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // constant path
	if err != nil {
		return prev, err
	}
	s := string(b)
	cur := iniValue(s, section, key)
	switch {
	case want != "" && cur != want:
		s = setINIValue(s, section, key, want)
	case want == "" && prev != "" && cur == prev:
		s = removeINIKey(s, section, key)
	default:
		return want, nil // already right, or changed by hand and not ours any more
	}
	_, err = writeIfChanged(path, s, 0o644)
	return want, err
}

// removeINIKey drops key from section.
func removeINIKey(s, section, key string) string {
	var out []string
	cur := ""
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur = t[1 : len(t)-1]
		} else if k, _, ok := strings.Cut(t, "="); ok && cur == section && strings.TrimSpace(k) == key {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
