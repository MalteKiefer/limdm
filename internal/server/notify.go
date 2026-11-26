package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

// Notifications: events go to channels (email, Slack, Discord, a signed
// webhook). Each channel subscribes to event types; delivery runs in the
// background with retries and is logged per channel.

// notifyEvents are the event types a channel can subscribe to.
var notifyEvents = []struct{ Type, Label string }{
	{"device.noncompliant", "Device became non-compliant"},
	{"device.tamper", "Tamper attempt on a device"},
	{"device.enrolled", "Device enrolled"},
	{"command.failed", "Lock, wipe, lost mode or script failed"},
	{"agent.update_failed", "Agent update failed and rolled back"},
	{"catalog.request", "App requested by a user"},
	{"directory.user_disabled", "Device user disabled in the directory"},
	{"recovery.view", "Recovery key viewed"},
	{"command.wipe_lost", "Wipe or lost mode sent"},
	{"command.script", "Script sent to a device"},
	{"user.role_change", "Console user role changed"},
	{"approval.request", "Four eyes approval requested"},
	{"audit.broken", "Audit log verification failed"},
	{"network.crl_token", "Network CRL token rotated"},
	{"keys.rotate", "Key rotation started or finished"},
}

// notifyCommand announces privileged commands once they are queued.
func (s *Server) notifyCommand(actor, deviceID, typ string) {
	switch typ {
	case "wipe", "lost":
		s.notifyDevice(deviceID, []notice{{Type: "command.wipe_lost", Severity: "critical", Title: actionTitle[typ] + " sent",
			Text: actionTitle[typ] + " was sent by " + actor + "."}})
	case "script":
		s.notifyDevice(deviceID, []notice{{Type: "command.script", Severity: "warning", Title: "Script sent",
			Text: "A script was sent by " + actor + "; the audit log has its text."}})
	}
}

var actionTitle = map[string]string{"wipe": "Wipe", "lost": "Lost mode"}

// notifyRoleChange announces a changed console role.
func (s *Server) notifyRoleChange(actor, login, from, to, approver string) {
	text := fmt.Sprintf("%s changed the role of %s from %s to %s.", actor, login, from, to)
	if approver != "" {
		text += " Approved by " + approver + "."
	}
	s.notify(notice{Type: "user.role_change", Severity: "warning", Title: "Console role changed: " + login, Text: text, URL: s.cfg.PublicURL + "/users"})
}

// notice is one event as channels show it.
type notice struct {
	Type     string    `json:"type"`
	Title    string    `json:"title"`
	Text     string    `json:"text"`
	Severity string    `json:"severity"` // info | warning | critical
	DeviceID string    `json:"device_id,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	URL      string    `json:"console_url,omitempty"`
	At       time.Time `json:"at"`
	Tenant   int64     `json:"-"` // tenant of the device; 0 reaches global channels only
}

type channel struct {
	ID      int64
	Name    string
	Kind    string // email | slack | discord | webhook
	Config  channelConfig
	Secret  string // opened: webhook URL, or the SMTP password
	Events  []string
	Enabled bool
	Tenant  *int64 // nil: a global channel that gets the events of every tenant
}

// channelConfig holds what is not secret; Slack, Discord and webhook URLs
// are credentials and live in the sealed secret.
type channelConfig struct {
	Host string   `json:"host,omitempty"` // SMTP
	Port int      `json:"port,omitempty"`
	TLS  string   `json:"tls,omitempty"` // starttls | tls
	User string   `json:"user,omitempty"`
	From string   `json:"from,omitempty"`
	To   []string `json:"to,omitempty"`
}

var smtpHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// validateChannel checks a channel before it is stored.
func validateChannel(c channel) error {
	if c.Name == "" || len(c.Name) > 80 {
		return errors.New("name: 1 to 80 characters")
	}
	for _, e := range c.Events {
		if !slices.ContainsFunc(notifyEvents, func(n struct{ Type, Label string }) bool { return n.Type == e }) {
			return fmt.Errorf("unknown event %q", e)
		}
	}
	switch c.Kind {
	case "slack":
		if !strings.HasPrefix(c.Secret, "https://hooks.slack.com/") {
			return errors.New("slack: an incoming webhook URL (https://hooks.slack.com/…)")
		}
	case "discord":
		u, err := url.Parse(c.Secret)
		if err != nil || u.Scheme != "https" || !slices.Contains([]string{"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}, u.Host) ||
			!strings.HasPrefix(u.Path, "/api/webhooks/") {
			return errors.New("discord: a webhook URL (https://discord.com/api/webhooks/…)")
		}
	case "webhook":
		if u, err := url.Parse(c.Secret); err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("webhook: an https URL")
		}
	case "email":
		cfg := c.Config
		if !smtpHostRe.MatchString(cfg.Host) || cfg.Port < 1 || cfg.Port > 65535 || (cfg.TLS != "starttls" && cfg.TLS != "tls") {
			return errors.New("email: SMTP host, port and TLS mode (starttls or tls) are required; plain SMTP is not supported")
		}
		if _, err := mail.ParseAddress(cfg.From); err != nil {
			return errors.New("email: invalid sender address")
		}
		if len(cfg.To) == 0 || len(cfg.To) > 20 {
			return errors.New("email: 1 to 20 recipients")
		}
		for _, to := range cfg.To {
			if _, err := mail.ParseAddress(to); err != nil {
				return fmt.Errorf("email: invalid recipient %q", to)
			}
		}
	default:
		return errors.New("kind is email, slack, discord or webhook")
	}
	return nil
}

// ---- formats ----

// slackEscape keeps host and user names from forming Slack links or mentions.
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func slackBody(n notice) ([]byte, error) {
	text := "*" + slackEscape.Replace(n.Title) + "*\n" + slackEscape.Replace(n.Text)
	if n.URL != "" {
		text += "\n<" + n.URL + "|Open in LiMDM>"
	}
	return json.Marshal(map[string]any{"text": text})
}

func discordBody(n notice) ([]byte, error) {
	color := map[string]int{"critical": 0xE01B24, "warning": 0xF5C211}[n.Severity]
	if color == 0 {
		color = 0x0F6E6E
	}
	embed := map[string]any{"title": n.Title, "description": n.Text, "color": color, "timestamp": n.At.Format(time.RFC3339)}
	if n.URL != "" {
		embed["url"] = n.URL
	}
	// no mentions: the text contains host and user names
	return json.Marshal(map[string]any{"embeds": []any{embed}, "allowed_mentions": map[string]any{"parse": []string{}}})
}

// emailMessage builds an RFC 5322 message. Header values are encoded and
// the body is quoted-printable with control characters removed, so text
// from devices (host names, command output) cannot add headers or SMTP lines.
func emailMessage(from string, to []string, n notice) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n",
		from, strings.Join(to, ", "), mime.QEncoding.Encode("utf-8", "[LiMDM] "+cleanText(n.Title)), n.At.Format(time.RFC1123Z))
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	body := cleanText(n.Text)
	if n.URL != "" {
		body += "\n\n" + cleanText(n.URL)
	}
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	_ = qp.Close()
	return b.Bytes()
}

// cleanText keeps printable text, line feeds and tabs.
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f && !unicode.IsControl(r)) {
			return r
		}
		return -1
	}, s)
}

// ---- delivery ----

// safeDialer refuses loopback, link-local (cloud metadata at 169.254.169.254)
// and unspecified addresses after name resolution, so a channel cannot be
// pointed at the server itself. Private networks stay allowed (an internal
// SIEM or mail relay).
var safeDialer = &net.Dialer{Timeout: 15 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if !targetAllowed(net.ParseIP(host)) {
		return fmt.Errorf("notification target %s is not allowed", host)
	}
	return nil
}}

func targetAllowed(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

// proxyChecked uses the proxy from the environment, but checks the target
// itself first: through a proxy, the dialer only sees the proxy's address.
// The proxy, configured by the operator, may be on loopback.
func proxyChecked(req *http.Request) (*url.URL, error) {
	u, err := http.ProxyFromEnvironment(req)
	if u == nil || err != nil {
		return u, err
	}
	host := req.URL.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if !targetAllowed(ip) {
			return nil, fmt.Errorf("notification target %s is not allowed", host)
		}
		return u, nil
	}
	ips, err := net.DefaultResolver.LookupIP(req.Context(), "ip", host)
	if err != nil {
		// egress only through the proxy, without outside DNS on this host: the
		// proxy resolves and enforces its own rules (channel URLs are set by
		// admins only)
		return u, nil //nolint:nilerr // see above
	}
	for _, ip := range ips {
		if !targetAllowed(ip) {
			return nil, fmt.Errorf("notification target %s is not allowed", req.URL.Hostname())
		}
	}
	return u, nil
}

// proxyAddr is the host:port the transport dials for proxy p (the scheme's
// default port when the URL names none).
func proxyAddr(p *url.URL) string {
	port := p.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}[p.Scheme]
	}
	return net.JoinHostPort(p.Hostname(), port)
}

// notifyDial dials the target through safeDialer, a configured proxy directly.
func notifyDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if p, _ := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: "limdm.invalid"}}); p != nil && proxyAddr(p) == addr {
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
	}
	return safeDialer.DialContext(ctx, network, addr)
}

var notifyClient = &http.Client{
	Timeout:       10 * time.Second,
	Transport:     &http.Transport{DialContext: notifyDial, Proxy: proxyChecked, TLSHandshakeTimeout: 10 * time.Second},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, // no redirects to internal addresses
}

func (s *Server) postJSON(ctx context.Context, target string, body []byte, signed bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if signed { // same scheme as the legacy webhook: timestamp and body under HMAC
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, s.webhookKey())
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		req.Header.Set("X-LiMDM-Timestamp", ts)
		req.Header.Set("X-LiMDM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := s.hooks
	if client == nil {
		client = notifyClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("answered %s", resp.Status)
	}
	return nil
}

func sendEmail(ctx context.Context, cfg channelConfig, password string, n notice) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := safeDialer
	tc := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if cfg.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tc}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()
	if cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("the SMTP server offers no STARTTLS")
		}
		if err := c.StartTLS(tc); err != nil {
			return err
		}
	}
	if cfg.User != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.User, password, cfg.Host)); err != nil {
			return err
		}
	}
	from, _ := mail.ParseAddress(cfg.From)
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	for _, to := range cfg.To {
		a, _ := mail.ParseAddress(to)
		if err := c.Rcpt(a.Address); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(emailMessage(cfg.From, cfg.To, n)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (s *Server) deliver(ctx context.Context, c channel, n notice) error {
	switch c.Kind {
	case "slack":
		b, err := slackBody(n)
		if err != nil {
			return err
		}
		return s.postJSON(ctx, c.Secret, b, false)
	case "discord":
		b, err := discordBody(n)
		if err != nil {
			return err
		}
		return s.postJSON(ctx, c.Secret, b, false)
	case "webhook":
		b, err := json.Marshal(n)
		if err != nil {
			return err
		}
		return s.postJSON(ctx, c.Secret, b, true)
	case "email":
		return sendEmail(ctx, c.Config, c.Secret, n)
	}
	return errors.New("unknown channel kind")
}

// notify sends an event to every enabled channel that subscribed to it, in
// the background: three attempts (now, after 10 s, after a minute), each
// logged. Never blocks the caller.
func (s *Server) notify(n notice) {
	if n.At.IsZero() {
		n.At = time.Now().UTC()
	}
	go func() {
		ctx := context.Background()
		chans, err := s.loadChannels(ctx, true)
		if err != nil {
			s.log.Error("notifications", "err", err)
			return
		}
		_, _ = s.db.Exec(ctx, `DELETE FROM notification_log WHERE at < now() - interval '30 days'`) // retention
		for _, c := range chans {
			if len(c.Events) > 0 && !slices.Contains(c.Events, n.Type) || c.Tenant != nil && *c.Tenant != n.Tenant {
				continue
			}
			go s.deliverWithRetry(c, n)
		}
	}()
}

func (s *Server) deliverWithRetry(c channel, n notice) {
	var err error
	for i, wait := range []time.Duration{0, 10 * time.Second, time.Minute} {
		time.Sleep(wait)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = s.deliver(ctx, c, n)
		cancel()
		if err == nil || i == 2 {
			break
		}
	}
	msg := ""
	if err != nil {
		msg = truncate(err.Error(), 500)
		s.log.Warn("notification not delivered", "channel", c.Name, "event", n.Type, "err", msg)
	}
	if _, lerr := s.db.Exec(context.Background(), `INSERT INTO notification_log(channel_id, event, ok, error) VALUES ($1,$2,$3,$4)`,
		c.ID, n.Type, err == nil, msg); lerr != nil {
		s.log.Error("notification log", "err", lerr)
	}
}

// loadChannels reads channels with their secrets opened.
func (s *Server) loadChannels(ctx context.Context, enabledOnly bool) ([]channel, error) {
	q := `SELECT id, name, kind, config, secret, events, enabled, tenant_id FROM notification_channels`
	if enabledOnly {
		q += ` WHERE enabled`
	}
	rows, err := s.db.Query(ctx, q+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (channel, error) {
		var c channel
		var cfg []byte
		var sealed string
		if err := row.Scan(&c.ID, &c.Name, &c.Kind, &cfg, &sealed, &c.Events, &c.Enabled, &c.Tenant); err != nil {
			return c, err
		}
		if err := json.Unmarshal(cfg, &c.Config); err != nil {
			return c, err
		}
		secret, err := s.openField(channelField(c.ID), sealed)
		c.Secret = secret
		return c, err
	})
}

// channelField binds a sealed secret to its channel.
func channelField(id int64) string { return "notification_channel:" + strconv.FormatInt(id, 10) }

// ---- console ----

// channelView is a channel as the settings page lists it: no secrets.
type channelView struct {
	ID                 int64
	Name, Kind, Target string
	Events             []string // labels of the subscribed events
	Enabled            bool
	LastOK             *bool
	LastError, LastEv  string
	LastAt             *time.Time
}

// channelOwned reports whether the tenant a request acts for owns c (the
// global view owns every channel).
func channelOwned(ctx context.Context, c channel) bool {
	t := ctxTenant(ctx)
	return t == 0 || c.Tenant != nil && *c.Tenant == t
}

func (s *Server) channelViews(ctx context.Context) ([]channelView, error) {
	chans, err := s.loadChannels(ctx, false)
	if err != nil {
		return nil, err
	}
	var out []channelView
	for _, c := range chans {
		if !channelOwned(ctx, c) {
			continue
		}
		v := channelView{ID: c.ID, Name: c.Name, Kind: c.Kind, Enabled: c.Enabled}
		for _, e := range c.Events {
			label := e
			for _, n := range notifyEvents {
				if n.Type == e {
					label = n.Label
				}
			}
			v.Events = append(v.Events, label)
		}
		switch c.Kind {
		case "email":
			v.Target = strings.Join(c.Config.To, ", ") + " via " + c.Config.Host
		default:
			if u, err := url.Parse(c.Secret); err == nil {
				v.Target = u.Host // the path is the credential
			}
		}
		var ok bool
		var e, ev string
		var at time.Time
		if err := s.db.QueryRow(ctx, `SELECT ok, error, event, at FROM notification_log WHERE channel_id=$1 ORDER BY id DESC LIMIT 1`, c.ID).Scan(&ok, &e, &ev, &at); err == nil {
			v.LastOK, v.LastError, v.LastEv, v.LastAt = &ok, e, ev, &at
		}
		out = append(out, v)
	}
	return out, nil
}

// channelSave adds a channel from the settings form.
func (s *Server) channelSave(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	port, _ := strconv.Atoi(r.FormValue("smtp_port"))
	c := channel{Name: strings.TrimSpace(r.FormValue("name")), Kind: r.FormValue("kind"), Events: r.Form["events"], Enabled: true,
		Config: channelConfig{Host: strings.TrimSpace(r.FormValue("smtp_host")), Port: port, TLS: r.FormValue("smtp_tls"),
			User: strings.TrimSpace(r.FormValue("smtp_user")), From: strings.TrimSpace(r.FormValue("smtp_from")), To: strings.Fields(strings.ReplaceAll(r.FormValue("smtp_to"), ",", " "))}}
	c.Secret = strings.TrimSpace(r.FormValue("url"))
	if c.Kind == "email" {
		c.Secret = r.FormValue("smtp_password")
	} else {
		c.Config = channelConfig{}
	}
	if err := validateChannel(c); err != nil {
		s.renderSettings(w, r, sess, s.settings(), "", err.Error())
		return
	}
	cfg, _ := json.Marshal(c.Config)
	events := append([]string{}, c.Events...)
	err := s.auditAction(ctx, sess.Email, "notification.channel_add", c.Name, c.Kind, func(tx pgx.Tx) error {
		var id int64
		if err := tx.QueryRow(ctx, `INSERT INTO notification_channels(name, kind, config, events, tenant_id) VALUES ($1,$2,$3,$4,nullif($5::bigint, 0)) RETURNING id`,
			c.Name, c.Kind, cfg, events, ctxTenant(ctx)).Scan(&id); err != nil {
			return err
		}
		sealed, err := s.sealField(channelField(id), c.Secret)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE notification_channels SET secret=$2 WHERE id=$1`, id, sealed)
		return err
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			s.renderSettings(w, r, sess, s.settings(), "", "A channel with this name exists already.")
			return
		}
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/settings?tab=notifications", http.StatusSeeOther)
}

// channelOp tests, switches on or off, or deletes a channel.
func (s *Server) channelOp(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	op := r.PathValue("op")
	if err != nil || !slices.Contains([]string{"test", "enable", "disable", "delete"}, op) {
		http.NotFound(w, r)
		return
	}
	if op == "test" {
		chans, err := s.loadChannels(ctx, false)
		if err != nil {
			s.fail(w, err)
			return
		}
		i := slices.IndexFunc(chans, func(c channel) bool { return c.ID == id && channelOwned(ctx, c) })
		if i < 0 {
			http.NotFound(w, r)
			return
		}
		n := notice{Type: "test", Severity: "info", Title: "Test notification", At: time.Now().UTC(),
			Text: "LiMDM can reach this channel. Sent by " + sess.Email + ".", URL: s.cfg.PublicURL + "/settings?tab=notifications"}
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = s.deliver(tctx, chans[i], n)
		cancel()
		msg := ""
		if err != nil {
			msg = truncate(err.Error(), 500)
		}
		_, _ = s.db.Exec(ctx, `INSERT INTO notification_log(channel_id, event, ok, error) VALUES ($1,'test',$2,$3)`, id, err == nil, msg)
		if err != nil {
			s.renderSettings(w, r, sess, s.settings(), "", "Test failed: "+msg)
			return
		}
		http.Redirect(w, r, "/settings?tab=notifications", http.StatusSeeOther)
		return
	}
	err = s.auditAction(ctx, sess.Email, "notification.channel_"+op, strconv.FormatInt(id, 10), "", func(tx pgx.Tx) error {
		if err := tenantGuard(ctx, tx, "notification_channels", id); err != nil {
			return err
		}
		var err error
		if op == "delete" {
			_, err = tx.Exec(ctx, `DELETE FROM notification_channels WHERE id=$1`, id)
		} else {
			_, err = tx.Exec(ctx, `UPDATE notification_channels SET enabled=$2, updated_at=now() WHERE id=$1`, id, op == "enable")
		}
		return err
	})
	if ue := (*userError)(nil); errors.As(err, &ue) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/settings?tab=notifications", http.StatusSeeOther)
}
