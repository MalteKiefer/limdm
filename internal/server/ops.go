package server

import (
	"log/slog"
	"net/netip"
	"sync/atomic"
)

// LogLevel is the level of the server log. limdm-server sets it from
// LIMDM_LOG_LEVEL at the start; Settings, Operations changes it at runtime.
var LogLevel = new(slog.LevelVar)

// ops are the operations settings in effect; before the settings are loaded
// (and in tests without them) those of the environment.
func (s *Server) ops() OpsSettings {
	if rt := s.rt.Load(); rt != nil {
		return rt.set.Ops
	}
	return envSettings(s.cfg).Ops
}

// proxySources are the load balancers whose PROXY v2 header the agent
// listener reads; none: PROXY protocol is off.
func (s *Server) proxySources() []netip.Prefix {
	if rt := s.rt.Load(); rt != nil {
		return rt.proxy
	}
	return s.cfg.AgentProxyFrom
}

// applyOps puts the operations settings of rt into effect in this instance.
// Settings saved on another instance arrive through reloadSettings.
func (s *Server) applyOps(rt *runtimeState) {
	o := rt.set.Ops
	_ = LogLevel.UnmarshalText([]byte(o.LogLevel)) // validated by prepare
	s.downloads.resize(o.UpdateDownloads)
	s.checkins.resize(o.MaxCheckins)
	s.bigCheckins.resize(o.MaxCheckins / 8)
}

// slots is a semaphore whose size changes at runtime: a new size swaps in
// a new channel, and holders release into the channel they took.
// ponytail: right after a resize the holders of the old and the new channel
// add up; fine for load limits, a counting semaphore if it must be exact.
type slots struct{ c atomic.Pointer[chan struct{}] }

func newSlots(n int) *slots {
	s := &slots{}
	s.resize(n)
	return s
}

// resize sets the size (at least 1); a nil slots stays unlimited.
func (s *slots) resize(n int) {
	if s == nil {
		return
	}
	n = max(n, 1)
	if c := s.c.Load(); c != nil && cap(*c) == n {
		return
	}
	c := make(chan struct{}, n)
	s.c.Store(&c)
}

// get is the channel to take a slot from; nil (no limit) for a nil slots.
func (s *slots) get() chan struct{} {
	if s == nil {
		return nil
	}
	return *s.c.Load()
}
