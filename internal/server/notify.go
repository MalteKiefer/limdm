package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
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
	{"backup.failed", "Backup failed or stored backup damaged"},
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

// localNotice translates the title and text of n into lang: a known text as
// a whole, else a known prefix before ": " ("Command failed: wipe"). Device
// data (host names, user names, output) stays as it is.
func localNotice(lang string, n notice) notice {
	tr := func(s string) string {
		if t := translate(lang, s); t != s {
			return t
		}
		if head, rest, ok := strings.Cut(s, ": "); ok {
			if t := translate(lang, head); t != head {
				return t + ": " + rest
			}
		}
		return s
	}
	n.Title, n.Text = tr(n.Title), tr(n.Text)
	return n
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
	Lang string   `json:"lang,omitempty"` // email, Slack and Discord text; English when empty
}

var smtpHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// validateChannel checks a channel before it is stored.
func validateChannel(c channel) error {
	if c.Config.Lang != "" && !knownLang(c.Config.Lang) {
		return errors.New("lang: one of " + strings.Join(langs, ", "))
	}
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

// Titles and texts carry what devices and users report (host names, user
// names, command output, tamper details). They must not become links,
// mentions or formatting in chat channels.

// slackEscape keeps host and user names from forming Slack links or mentions.
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// defang breaks URLs so chat clients do not turn them into links.
func defang(s string) string { return strings.ReplaceAll(s, "://", ":\u200b//") }

// slackBody shows title and text as plain_text blocks, which Slack never
// renders as formatting or links; only the console link is mrkdwn. The
// escaped fallback text is what notifications show.
func slackBody(lang string, n notice) ([]byte, error) {
	plain := func(s string, max int) map[string]any {
		return map[string]any{"type": "plain_text", "text": truncate(defang(cleanText(s)), max), "emoji": false}
	}
	blocks := []any{map[string]any{"type": "header", "text": plain(firstNonEmpty(n.Title, "LiMDM"), 150)}}
	if n.Text != "" {
		blocks = append(blocks, map[string]any{"type": "section", "text": plain(n.Text, 3000)})
	}
	if n.URL != "" {
		blocks = append(blocks, map[string]any{"type": "context", "elements": []any{map[string]any{"type": "mrkdwn", "text": "<" + n.URL + "|" + slackEscape.Replace(translate(lang, "Open in LiMDM")) + ">"}}})
	}
	return json.Marshal(map[string]any{"text": slackEscape.Replace(defang(n.Title)), "blocks": blocks, "unfurl_links": false, "unfurl_media": false})
}

// discordEscape matches the characters Discord markdown gives a meaning
// (formatting, masked links, headings, lists, quotes, mentions).
var discordEscape = regexp.MustCompile("[\\\\*_~`|>#\\-\\[\\]()<@:]")

// discordText escapes markdown with backslashes and defangs URLs.
func discordText(s string) string { return defang(discordEscape.ReplaceAllString(s, `\$0`)) }

func discordBody(n notice) ([]byte, error) {
	color := map[string]int{"critical": 0xE01B24, "warning": 0xF5C211}[n.Severity]
	if color == 0 {
		color = 0x0F6E6E
	}
	embed := map[string]any{"title": discordText(n.Title), "description": discordText(n.Text), "color": color, "timestamp": n.At.Format(time.RFC3339)}
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
	rcpt := make([]string, 0, len(to))
	for _, t := range to {
		rcpt = append(rcpt, headerAddress(t))
	}
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n",
		headerAddress(from), strings.Join(rcpt, ", "), mime.QEncoding.Encode("utf-8", "[LiMDM] "+oneLine(cleanText(n.Title))), n.At.Format(time.RFC1123Z))
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

// headerAddress is an address as a header value: parsed with net/mail and
// written back by it (names encoded), never raw text; one line in any case.
func headerAddress(s string) string {
	a, err := mail.ParseAddress(s)
	if err != nil {
		return ""
	}
	return oneLine(a.String())
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
// pointed at the server itself, and private networks unless the request
// may reach them (withPrivate).
var safeDialer = &net.Dialer{Timeout: 15 * time.Second, ControlContext: func(ctx context.Context, _, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if !targetAllowed(ctx, net.ParseIP(host)) {
		return fmt.Errorf("notification target %s is not allowed", host)
	}
	return nil
}}

type privateKey struct{}

// withPrivate lets a delivery reach private networks: global channels and
// the compliance webhook with Settings NotifyPrivate on, never tenant channels.
func withPrivate(ctx context.Context, ok bool) context.Context {
	return context.WithValue(ctx, privateKey{}, ok)
}

func privateAllowed(ctx context.Context) bool {
	ok, _ := ctx.Value(privateKey{}).(bool)
	return ok
}

// sharedSpace is RFC 6598 shared address space (carrier NAT, also some
// cloud metadata services such as 100.100.100.200).
var sharedSpace = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func targetAllowed(ctx context.Context, ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.IsPrivate() || sharedSpace.Contains(ip) {
		return privateAllowed(ctx)
	}
	return true
}

// notifyPrivate is the setting for global channels (false before settings load).
func (s *Server) notifyPrivate() bool {
	rt := s.rt.Load()
	return rt != nil && rt.set.NotifyPrivate
}

type proxyKey struct{}

// pinnedTransport routes requests through the proxy of the environment
// (HTTPS_PROXY, HTTP_PROXY, NO_PROXY) without letting the proxy resolve
// the target: the proxy is only chosen here and dialPinned opens the
// tunnel to an address this host resolved and checked. A proxy resolving
// the name again could get another answer (DNS rebinding) and reach an
// address targetAllowed refuses.
type pinnedTransport struct{ *http.Transport }

func (t pinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return nil, err
	}
	return t.Transport.RoundTrip(req.WithContext(context.WithValue(req.Context(), proxyKey{}, p)))
}

// dialPinned dials addr with direct, or through the proxy pinnedTransport
// chose: the name is resolved here, every address must pass
// targetAllowed, and a CONNECT tunnel goes to the first one (TLS still
// checks the certificate for the name). Without local DNS a request that
// may reach private networks lets the proxy resolve, as egress only
// through the proxy needs.
func dialPinned(ctx context.Context, network, addr string, direct func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	p, _ := ctx.Value(proxyKey{}).(*url.URL)
	if p == nil {
		return direct(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	target := addr
	ips := []net.IP{net.ParseIP(host)}
	if ips[0] == nil {
		if ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host); err != nil && !privateAllowed(ctx) {
			return nil, fmt.Errorf("target %s cannot be resolved to check it: %w", host, err)
		}
	}
	for _, ip := range ips {
		if !targetAllowed(ctx, ip) {
			return nil, fmt.Errorf("target %s is not allowed", host)
		}
	}
	if len(ips) > 0 {
		target = net.JoinHostPort(ips[0].String(), port)
	}
	return proxyConnect(ctx, p, target)
}

// proxyConnect opens a CONNECT tunnel to target through an http or https
// proxy (with the credentials of its URL).
func proxyConnect(ctx context.Context, p *url.URL, target string) (net.Conn, error) {
	port := p.Port()
	switch {
	case p.Scheme != "http" && p.Scheme != "https":
		return nil, fmt.Errorf("proxy scheme %s is not supported, use an http or https proxy", p.Scheme)
	case port == "" && p.Scheme == "https":
		port = "443"
	case port == "":
		port = "80"
	}
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(p.Hostname(), port))
	if err != nil {
		return nil, err
	}
	if p.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: p.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: http.Header{}}
	if u := p.User; u != nil {
		pw, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	// the target speaks only after the client, so the reader holds nothing
	// beyond the answer
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy refused the tunnel to %s: %s", target, resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func notifyDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialPinned(ctx, network, addr, safeDialer.DialContext)
}

var notifyClient = &http.Client{
	Timeout: 10 * time.Second,
	// no idle connections: a pooled connection skips the dial check, so a
	// tenant channel could reuse one a global channel opened to a private
	// address (NotifyPrivate)
	Transport:     pinnedTransport{&http.Transport{DialContext: notifyDial, TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true}},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, // no redirects to internal addresses
}

// postJSON posts body. signed adds X-LiMDM-Signature: for a global channel
// (tenant nil) the scheme of the compliance webhook, HMAC over timestamp
// "." body with the webhook secret; for a tenant channel HMAC over
// timestamp "." tenant ID "." body with the tenant's own secret, so a
// tenant's signed events cannot be replayed to another tenant's receiver.
func (s *Server) postJSON(ctx context.Context, target string, body []byte, signed bool, tenant *int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if signed {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		key, prefix := s.webhookKey(), ts+"."
		if tenant != nil {
			id := strconv.FormatInt(*tenant, 10)
			key, prefix = s.tenantWebhookKey(*tenant), ts+"."+id+"."
			req.Header.Set("X-LiMDM-Tenant", id)
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(prefix))
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
	if err := smtpData(c, emailMessage(cfg.From, cfg.To, n)); err != nil {
		return err
	}
	return c.Quit()
}

// smtpData sends the DATA command with msg, as smtp.Client.Data and its
// writer's Close do. msg comes from emailMessage only: every header value is
// one line (addresses written by net/mail, the subject Q encoded) and the
// body is quoted-printable, so device text cannot add headers or recipients.
func smtpData(c *smtp.Client, msg []byte) error {
	id, err := c.Text.Cmd("DATA")
	if err != nil {
		return err
	}
	c.Text.StartResponse(id)
	_, _, err = c.Text.ReadResponse(354)
	c.Text.EndResponse(id)
	if err != nil {
		return err
	}
	w := c.Text.DotWriter()
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, _, err = c.Text.ReadResponse(250)
	return err
}

func (s *Server) deliver(ctx context.Context, c channel, n notice) error {
	ctx = withPrivate(ctx, c.Tenant == nil && s.notifyPrivate())
	if c.Kind != "webhook" { // webhooks are read by programs: English
		n = localNotice(c.Config.Lang, n)
	}
	switch c.Kind {
	case "slack":
		b, err := slackBody(c.Config.Lang, n)
		if err != nil {
			return err
		}
		return s.postJSON(ctx, c.Secret, b, false, nil)
	case "discord":
		b, err := discordBody(n)
		if err != nil {
			return err
		}
		return s.postJSON(ctx, c.Secret, b, false, nil)
	case "webhook":
		b, err := json.Marshal(n)
		if err != nil {
			return err
		}
		return s.postJSON(ctx, c.Secret, b, true, c.Tenant)
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

// tenantDeliveryError replaces delivery errors for tenant accounts, so a
// channel cannot be used to probe networks (open, closed, TLS, banners).
const tenantDeliveryError = "Test failed: the target did not accept the message. Check the URL or the mail settings."

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
			if e != "" && ctxTenant(ctx) != 0 {
				e = tenantDeliveryError
			}
			v.LastOK, v.LastError, v.LastEv, v.LastAt = &ok, e, ev, &at
		}
		out = append(out, v)
	}
	return out, nil
}

// addChannel stores a new enabled channel of the tenant the request acts
// for (global in the global view). The console form and the admin API both
// call it.
func (s *Server) addChannel(ctx context.Context, sess session, c channel) (int64, error) {
	c.Name, c.Enabled = strings.TrimSpace(c.Name), true
	if c.Kind == "email" {
		c.Config.Host, c.Config.User, c.Config.From = strings.TrimSpace(c.Config.Host), strings.TrimSpace(c.Config.User), strings.TrimSpace(c.Config.From)
	} else {
		c.Secret, c.Config = strings.TrimSpace(c.Secret), channelConfig{}
	}
	if err := validateChannel(c); err != nil {
		return 0, &userError{http.StatusUnprocessableEntity, err.Error()}
	}
	cfg, _ := json.Marshal(c.Config)
	events := append([]string{}, c.Events...)
	var id int64
	err := s.auditAction(ctx, sess.Email, "notification.channel_add", c.Name, c.Kind, func(tx pgx.Tx) error {
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
	if isUnique(err) {
		return 0, &userError{http.StatusConflict, "A channel with this name exists already."}
	}
	return id, err
}

var errNoChannel = &userError{http.StatusNotFound, "notification channel not found"}

// testChannel sends a test notice to a channel the request's tenant owns
// and logs the result. A failure is a userError; tenant accounts get no
// network details (the server log has them).
func (s *Server) testChannel(ctx context.Context, sess session, id int64) error {
	chans, err := s.loadChannels(ctx, false)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(chans, func(c channel) bool { return c.ID == id && channelOwned(ctx, c) })
	if i < 0 {
		return errNoChannel
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
	if err != nil && ctxTenant(ctx) != 0 { // no network details for tenant accounts: the log has them
		s.log.Warn("notification test failed", "channel", id, "err", msg)
		return &userError{http.StatusBadGateway, tenantDeliveryError}
	}
	if err != nil {
		return &userError{http.StatusBadGateway, "Test failed: " + msg}
	}
	return nil
}

// setChannel switches a channel on or off (op enable, disable) or deletes it.
func (s *Server) setChannel(ctx context.Context, sess session, id int64, op string) error {
	err := s.auditAction(ctx, sess.Email, "notification.channel_"+op, strconv.FormatInt(id, 10), "", func(tx pgx.Tx) error {
		if err := tenantGuard(ctx, tx, "notification_channels", id); err != nil {
			return err
		}
		var tag interface{ RowsAffected() int64 }
		var err error
		if op == "delete" {
			tag, err = tx.Exec(ctx, `DELETE FROM notification_channels WHERE id=$1`, id)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE notification_channels SET enabled=$2, updated_at=now() WHERE id=$1`, id, op == "enable")
		}
		if err == nil && tag.RowsAffected() == 0 {
			err = errNoChannel
		}
		return err
	})
	if ue := (*userError)(nil); errors.As(err, &ue) {
		return errNoChannel
	}
	return err
}
