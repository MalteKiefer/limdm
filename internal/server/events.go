package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Live updates for the console app: GET /api/v1/events/stream is a server
// sent events stream with three event types, each limited to what the
// caller may read (tenant, device scope, role):
//
//	device    a device checked in: id, hostname, status, last_seen
//	activity  a new audit log entry: id, at, actor, action, target (admin and auditor)
//	inbox     the number of pending approvals changed: pending
//
// The client treats events as hints and refetches what it shows.
// ponytail: every stream polls the database (two indexed queries every few
// seconds); a shared LISTEN/NOTIFY hub when console users grow into hundreds.

const (
	eventPoll      = 3 * time.Second
	eventStreamFor = 4 * time.Minute // below the server's write timeout; EventSource reconnects
	eventStreamCap = 5               // open streams per login
)

var eventStreams = struct {
	sync.Mutex
	n map[string]int
}{n: map[string]int{}}

// eventStreamSlot takes one of the caller's stream slots; release returns it.
func eventStreamSlot(actor string) (release func(), ok bool) {
	eventStreams.Lock()
	defer eventStreams.Unlock()
	if eventStreams.n[actor] >= eventStreamCap {
		return nil, false
	}
	eventStreams.n[actor]++
	return func() {
		eventStreams.Lock()
		defer eventStreams.Unlock()
		if eventStreams.n[actor]--; eventStreams.n[actor] <= 0 {
			delete(eventStreams.n, actor)
		}
	}, true
}

type deviceEvent struct {
	ID       string     `json:"id"`
	Hostname string     `json:"hostname"`
	Status   string     `json:"status"`
	LastSeen *time.Time `json:"last_seen"`
}

type activityEvent struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
}

func (s *Server) apiEventStream(w http.ResponseWriter, r *http.Request, c apiCaller) {
	release, ok := eventStreamSlot(c.actor())
	if !ok {
		problem(w, http.StatusTooManyRequests, fmt.Sprintf("at most %d open event streams", eventStreamCap))
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), eventStreamFor)
	defer cancel()
	sess := c.sess()
	st := eventState{pending: -1}
	if err := s.db.QueryRow(ctx, `SELECT now(), coalesce(max(id), 0) FROM audit_log`).Scan(&st.since, &st.auditID); err != nil {
		s.apiFail(w, err)
		return
	}
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // nginx: pass events through at once
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 3000\n\n")
	t := time.NewTicker(eventPoll)
	defer t.Stop()
	for {
		if err := s.pollEvents(ctx, w, c, sess, &st); err != nil {
			if ctx.Err() == nil {
				s.log.Warn("event stream", "err", err, "request_id", requestID(w))
			}
			return
		}
		if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// eventState is what a stream has sent so far.
type eventState struct {
	since   time.Time // devices seen after this were not sent yet
	auditID int64     // last audit entry sent
	pending int       // pending approvals last sent, -1 before the first
}

func (s *Server) pollEvents(ctx context.Context, w http.ResponseWriter, c apiCaller, sess session, st *eventState) error {
	send := func(event string, v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		return err
	}
	var where sqlWhere
	scope, sargs := scopeCond(sess, 0)
	where.add(scope, sargs...)
	where.add(`d.last_seen > $1`, st.since)
	devs, err := s.listDevicesQuery(ctx, where.sql(), " ORDER BY d.last_seen LIMIT 500", where.args...)
	if err != nil {
		return err
	}
	for _, d := range devs {
		if err := send("device", deviceEvent{d.ID, d.Hostname, d.Status, d.LastSeen}); err != nil {
			return err
		}
		st.since = *d.LastSeen
	}
	if c.allows("audit") { // the audit log is not the helpdesk's to read
		cond, args := auditScope(sess, 1)
		rows, err := s.db.Query(ctx, `SELECT id, at, actor, action, target FROM audit_log WHERE id > $1 AND `+cond+` ORDER BY id LIMIT 200`, append([]any{st.auditID}, args...)...)
		if err != nil {
			return err
		}
		var list []activityEvent
		for rows.Next() {
			var a activityEvent
			if err := rows.Scan(&a.ID, &a.At, &a.Actor, &a.Action, &a.Target); err != nil {
				rows.Close()
				return err
			}
			list = append(list, a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, a := range list {
			if err := send("activity", a); err != nil {
				return err
			}
			st.auditID = a.ID
		}
	}
	cond, args := approvalCond(c, 0)
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE status='pending' AND expires_at > now() AND `+cond, args...).Scan(&n); err != nil {
		return err
	}
	if n != st.pending {
		st.pending = n
		return send("inbox", map[string]int{"pending": n})
	}
	return nil
}
