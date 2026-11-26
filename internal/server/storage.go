package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // Content-MD5 is an S3 integrity header (required with Object Lock), not a security control
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Storage targets for backups and uploaded packages: a local directory
// (also a mounted NFS share), an S3 compatible bucket (AWS, MinIO, Ceph,
// Hetzner, Wasabi) and an SFTP server. Other services are reached through
// rclone (docs/backup.md). Objects are written from a local file, so S3
// gets its checksums and SFTP and local writes can be renamed into place.

// blobStore is one storage target.
type blobStore interface {
	Put(ctx context.Context, name, file string) error
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	List(ctx context.Context, prefix string) ([]blobInfo, error)
	Delete(ctx context.Context, name string) error
}

type blobInfo struct {
	Name     string
	Size     int64
	Modified time.Time
}

// StoreTarget configures a storage target. Secrets are sealed with the
// session key (SecretEnc: S3 secret key, B2 application key, SFTP or WebDAV
// password or WebDAV token; KeyEnc: SFTP private key) and never rendered.
// B2 uses Region (us-west-004 ...), Bucket and AccessKey (the key id);
// WebDAV uses Endpoint (the folder URL) and User (empty: bearer token).
type StoreTarget struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // local | s3 | b2 | sftp | webdav
	Dir  string `json:"dir,omitempty"`
	// S3
	Endpoint  string `json:"endpoint,omitempty"` // https://s3.eu-central-1.amazonaws.com, https://fsn1.your-objectstorage.com ...
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	PathStyle bool   `json:"path_style,omitempty"`
	LockMode  string `json:"lock_mode,omitempty"` // "", GOVERNANCE or COMPLIANCE (S3 Object Lock)
	LockDays  int    `json:"lock_days,omitempty"`
	// SFTP
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
	User    string `json:"user,omitempty"`
	HostKey string `json:"host_key,omitempty"` // known_hosts style key or SHA256:... fingerprint

	SecretEnc string `json:"secret_enc,omitempty"`
	KeyEnc    string `json:"key_enc,omitempty"`
}

var (
	targetNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	s3PrefixRe   = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,200}$`)
)

func (t StoreTarget) validate() error {
	if !targetNameRe.MatchString(t.Name) {
		return errors.New("target name: lowercase letters, digits, - and _, up to 32 characters")
	}
	switch t.Kind {
	case "local":
		if !filepath.IsAbs(t.Dir) || filepath.Clean(t.Dir) != t.Dir {
			return errors.New("local target: an absolute, clean directory path")
		}
	case "s3":
		if u, err := url.Parse(t.Endpoint); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
			return errors.New("S3 target: the endpoint must be an https URL without path, e.g. https://s3.eu-central-1.amazonaws.com")
		}
		if t.Bucket == "" || t.AccessKey == "" || t.Region == "" {
			return errors.New("S3 target: bucket, region and access key are required")
		}
		if !s3PrefixRe.MatchString(t.Prefix) || strings.Contains(t.Prefix, "..") {
			return errors.New("S3 target: invalid prefix")
		}
		if t.LockMode != "" && t.LockMode != "GOVERNANCE" && t.LockMode != "COMPLIANCE" || t.LockMode != "" && (t.LockDays < 1 || t.LockDays > 3650) {
			return errors.New("S3 Object Lock: mode GOVERNANCE or COMPLIANCE with 1 to 3650 days")
		}
	case "sftp":
		if !hostOrIPName(t.Host) || t.User == "" || t.Port < 0 || t.Port > 65535 {
			return errors.New("SFTP target: host and user are required")
		}
		if t.HostKey == "" {
			return errors.New("SFTP target: the server host key is required (ssh-keyscan HOST, or its SHA256 fingerprint)")
		}
		if _, err := hostKeyCallback(t.HostKey); err != nil {
			return err
		}
		if !path.IsAbs(t.Dir) {
			return errors.New("SFTP target: an absolute directory path")
		}
	case "b2":
		if !b2RegionRe.MatchString(t.Region) || t.Bucket == "" || t.AccessKey == "" {
			return errors.New("B2 target: region (like us-west-004, from the bucket's endpoint), bucket and application key id are required")
		}
		if !s3PrefixRe.MatchString(t.Prefix) || strings.Contains(t.Prefix, "..") {
			return errors.New("B2 target: invalid prefix")
		}
		if t.LockMode != "" && t.LockMode != "GOVERNANCE" && t.LockMode != "COMPLIANCE" || t.LockMode != "" && (t.LockDays < 1 || t.LockDays > 3650) {
			return errors.New("B2 file lock: mode GOVERNANCE or COMPLIANCE with 1 to 3650 days")
		}
	case "webdav":
		if u, err := url.Parse(t.Endpoint); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
			return errors.New("WebDAV target: an https folder URL without credentials, e.g. https://cloud.example.com/remote.php/dav/files/backup/limdm")
		}
	default:
		return errors.New("target kind: local, s3, b2, sftp or webdav")
	}
	return nil
}

var b2RegionRe = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]{3}$`)

var hostNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$`)

func hostOrIPName(s string) bool { return net.ParseIP(s) != nil || hostNameRe.MatchString(s) }

// storeClient talks to S3, B2 and WebDAV targets. It follows no
// redirect (Go would resend the credentials to the same host over plain
// http, and a redirect could reach an internal host) and gives up on a
// server that does not answer, which would hold the backup lock forever.
// Bodies have no overall timeout: archives are large.
func storeClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 5 * time.Minute
	// through a proxy the target is resolved and pinned here (dialPinned):
	// private networks are fine for a backup target, loopback and link
	// local (cloud metadata) are not
	tr.Proxy = nil
	direct := (&net.Dialer{Timeout: 30 * time.Second}).DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialPinned(withPrivate(ctx, true), network, addr, direct)
	}
	return &http.Client{Transport: pinnedTransport{tr}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// openStore builds the store of a target with its secrets opened.
func (s *Server) openStore(t StoreTarget) (blobStore, error) {
	secret, err := s.openField("store."+t.Name+".secret", t.SecretEnc)
	if err != nil {
		return nil, fmt.Errorf("target %s: secret: %w", t.Name, err)
	}
	switch t.Kind {
	case "local":
		return localStore{dir: t.Dir}, nil
	case "s3":
		return &s3Store{endpoint: strings.TrimRight(t.Endpoint, "/"), region: t.Region, bucket: t.Bucket, prefix: t.Prefix,
			key: t.AccessKey, secret: secret, pathStyle: t.PathStyle, lockMode: t.LockMode, lockDays: t.LockDays,
			client: storeClient(), now: time.Now}, nil
	case "b2":
		// Backblaze's S3 compatible API: the same signing, multipart upload
		// for large files and Object Lock headers (file lock) as S3
		return &s3Store{endpoint: "https://s3." + t.Region + ".backblazeb2.com", region: t.Region, bucket: t.Bucket, prefix: t.Prefix,
			key: t.AccessKey, secret: secret, pathStyle: true, lockMode: t.LockMode, lockDays: t.LockDays,
			client: storeClient(), now: time.Now}, nil
	case "webdav":
		return &davStore{base: strings.TrimRight(t.Endpoint, "/"), user: t.User, secret: secret, client: storeClient()}, nil
	case "sftp":
		key, err := s.openField("store."+t.Name+".key", t.KeyEnc)
		if err != nil {
			return nil, fmt.Errorf("target %s: private key: %w", t.Name, err)
		}
		cb, err := hostKeyCallback(t.HostKey)
		if err != nil {
			return nil, err
		}
		var auth []ssh.AuthMethod
		if key != "" {
			signer, err := ssh.ParsePrivateKey([]byte(key))
			if err != nil {
				return nil, fmt.Errorf("target %s: private key: %w", t.Name, err)
			}
			auth = append(auth, ssh.PublicKeys(signer))
		}
		if secret != "" {
			auth = append(auth, ssh.Password(secret))
		}
		port := t.Port
		if port == 0 {
			port = 22
		}
		return &sftpStore{addr: net.JoinHostPort(t.Host, strconv.Itoa(port)), cfg: &ssh.ClientConfig{User: t.User, Auth: auth,
			HostKeyCallback: cb, Timeout: 20 * time.Second}, dir: t.Dir}, nil
	}
	return nil, fmt.Errorf("unknown target kind %q", t.Kind)
}

// hostKeyCallback pins the SFTP server key: a known_hosts or
// authorized_keys style line, or the SHA256 fingerprint ssh-keygen -l prints.
func hostKeyCallback(v string) (ssh.HostKeyCallback, error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "SHA256:") {
		return func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != v {
				return fmt.Errorf("SFTP host key %s does not match the configured %s", ssh.FingerprintSHA256(key), v)
			}
			return nil
		}, nil
	}
	fields := strings.Fields(v)
	if len(fields) >= 3 && !strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa-") {
		v = strings.Join(fields[1:], " ") // known_hosts: drop the host name column
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v))
	if err != nil {
		return nil, errors.New("SFTP host key: a key line (ssh-keyscan) or a SHA256:... fingerprint")
	}
	return ssh.FixedHostKey(key), nil
}

// ---- local directory ----

type localStore struct{ dir string }

func (l localStore) path(name string) (string, error) {
	p := filepath.Join(l.dir, filepath.FromSlash(name))
	if !strings.HasPrefix(p, filepath.Clean(l.dir)+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid object name %q", name)
	}
	return p, nil
}

func (l localStore) Put(_ context.Context, name, file string) error {
	dst, err := l.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	src, err := os.Open(file)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".put-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return err
	}
	if err := errors.Join(tmp.Sync(), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func (l localStore) Get(_ context.Context, name string) (io.ReadCloser, error) {
	p, err := l.path(name)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (l localStore) List(_ context.Context, prefix string) ([]blobInfo, error) {
	var out []blobInfo
	err := filepath.WalkDir(l.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return filepath.SkipAll
			}
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".put-") {
			return nil
		}
		rel, _ := filepath.Rel(l.dir, p)
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, prefix) {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out = append(out, blobInfo{Name: rel, Size: fi.Size(), Modified: fi.ModTime()})
		return nil
	})
	return out, err
}

func (l localStore) Delete(_ context.Context, name string) error {
	p, err := l.path(name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// ---- S3 (Signature Version 4) ----

type s3Store struct {
	endpoint, region, bucket, prefix, key, secret string
	pathStyle                                     bool
	lockMode                                      string
	lockDays                                      int
	client                                        *http.Client
	now                                           func() time.Time
}

// objectKey is the key of an object below the target prefix.
func (c *s3Store) objectKey(name string) string {
	if p := strings.Trim(c.prefix, "/"); p != "" {
		return p + "/" + name
	}
	return name
}

func (c *s3Store) objectURL(name string, q url.Values) *url.URL {
	u := c.bucketURL(q)
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + c.objectKey(name)
	return u
}

func (c *s3Store) bucketURL(q url.Values) *url.URL {
	u, _ := url.Parse(c.endpoint)
	if c.pathStyle {
		u.Path = "/" + c.bucket
	} else {
		u.Host = c.bucket + "." + u.Host
		u.Path = "/"
	}
	u.RawQuery = q.Encode()
	return u
}

// s3Escape encodes like AWS: everything except unreserved characters, and
// "/" too unless it separates path segments.
func s3Escape(s string, slash bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '.', c == '_', c == '~', c == '/' && !slash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// sign adds the SigV4 headers. payload is the hex SHA-256 of the body.
func (c *s3Store) sign(req *http.Request, payload string) {
	t := c.now().UTC()
	amzDate, day := t.Format("20060102T150405Z"), t.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payload)
	headers := map[string]string{"host": req.URL.Host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-md5" || lk == "range" || lk == "content-type" {
			headers[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	q := req.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var query []string
	for _, k := range keys {
		for _, v := range q[k] {
			query = append(query, s3Escape(k, true)+"="+s3Escape(v, true))
		}
	}
	signed := strings.Join(names, ";")
	canon := strings.Join([]string{req.Method, s3Escape(req.URL.Path, false), strings.Join(query, "&"), canonHeaders.String(), signed, payload}, "\n")
	scope := day + "/" + c.region + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(canon))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	k := hmacSHA256([]byte("AWS4"+c.secret), day)
	k = hmacSHA256(k, c.region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.key+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmacSHA256(k, toSign)))
}

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func (c *s3Store) do(ctx context.Context, method string, u *url.URL, body io.Reader, size int64, payload string, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	c.sign(req, payload)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		var e struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if xml.Unmarshal(b, &e) == nil && e.Code != "" {
			return nil, fmt.Errorf("S3 %s: %s: %s", method, e.Code, e.Message)
		}
		return nil, fmt.Errorf("S3 %s: %s", method, resp.Status)
	}
	return resp, nil
}

func (c *s3Store) Put(ctx context.Context, name, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	sh, mh := sha256.New(), md5.New() //nolint:gosec // Object Lock requires Content-MD5; SHA-256 signs the payload
	size, err := io.Copy(io.MultiWriter(sh, mh), f)
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/octet-stream")
	if c.lockMode != "" {
		hdr.Set("x-amz-object-lock-mode", c.lockMode)
		hdr.Set("x-amz-object-lock-retain-until-date", c.now().UTC().AddDate(0, 0, c.lockDays).Format(time.RFC3339))
	}
	if size > s3PartSize {
		return c.putMultipart(ctx, name, f, size, hdr)
	}
	hdr.Set("Content-MD5", base64.StdEncoding.EncodeToString(mh.Sum(nil)))
	resp, err := c.do(ctx, http.MethodPut, c.objectURL(name, nil), f, size, hex.EncodeToString(sh.Sum(nil)), hdr)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// s3PartSize splits large archives into multipart uploads (a single PUT
// takes at most 5 GiB on S3 and B2); a var so tests can lower it.
var s3PartSize int64 = 256 << 20

// putMultipart uploads in parts of s3PartSize; the Object Lock headers go
// with the creation, every part carries its Content-MD5. A failed upload
// is aborted so no parts are left behind.
func (c *s3Store) putMultipart(ctx context.Context, name string, f *os.File, size int64, hdr http.Header) error {
	resp, err := c.do(ctx, http.MethodPost, c.objectURL(name, url.Values{"uploads": {""}}), nil, 0, emptySHA256, hdr)
	if err != nil {
		return err
	}
	var start struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&start)
	resp.Body.Close()
	if err != nil || start.UploadID == "" {
		return fmt.Errorf("S3 multipart upload: no upload id: %w", err)
	}
	type part struct {
		Number int    `xml:"PartNumber"`
		ETag   string `xml:"ETag"`
	}
	var parts []part
	err = func() error {
		for off, n := int64(0), 1; off < size; off, n = off+s3PartSize, n+1 {
			sec := io.NewSectionReader(f, off, min(s3PartSize, size-off))
			sh, mh := sha256.New(), md5.New() //nolint:gosec // Content-MD5 per part, as above
			if _, err := io.Copy(io.MultiWriter(sh, mh), sec); err != nil {
				return err
			}
			h := http.Header{}
			h.Set("Content-MD5", base64.StdEncoding.EncodeToString(mh.Sum(nil)))
			q := url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {start.UploadID}}
			resp, err := c.do(ctx, http.MethodPut, c.objectURL(name, q), io.NewSectionReader(f, off, sec.Size()), sec.Size(), hex.EncodeToString(sh.Sum(nil)), h)
			if err != nil {
				return fmt.Errorf("part %d: %w", n, err)
			}
			resp.Body.Close()
			parts = append(parts, part{n, resp.Header.Get("ETag")})
		}
		body, _ := xml.Marshal(struct {
			XMLName xml.Name `xml:"CompleteMultipartUpload"`
			Parts   []part   `xml:"Part"`
		}{Parts: parts})
		sum := sha256.Sum256(body)
		resp, err := c.do(ctx, http.MethodPost, c.objectURL(name, url.Values{"uploadId": {start.UploadID}}), bytes.NewReader(body), int64(len(body)), hex.EncodeToString(sum[:]), nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if bytes.Contains(b, []byte("<Error>")) { // S3 may report a failed completion with 200
			return fmt.Errorf("S3 complete multipart upload: %s", truncate(string(b), 300))
		}
		return nil
	}()
	if err != nil {
		if r, aerr := c.do(context.WithoutCancel(ctx), http.MethodDelete, c.objectURL(name, url.Values{"uploadId": {start.UploadID}}), nil, 0, emptySHA256, nil); aerr == nil {
			r.Body.Close()
		}
	}
	return err
}

func (c *s3Store) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	resp, err := c.do(ctx, http.MethodGet, c.objectURL(name, nil), nil, 0, emptySHA256, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (c *s3Store) Delete(ctx context.Context, name string) error {
	resp, err := c.do(ctx, http.MethodDelete, c.objectURL(name, nil), nil, 0, emptySHA256, nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *s3Store) List(ctx context.Context, prefix string) ([]blobInfo, error) {
	full := c.objectKey(prefix)
	var out []blobInfo
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {full}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := c.do(ctx, http.MethodGet, c.bucketURL(q), nil, 0, emptySHA256, nil)
		if err != nil {
			return nil, err
		}
		var res struct {
			Contents []struct {
				Key          string    `xml:"Key"`
				Size         int64     `xml:"Size"`
				LastModified time.Time `xml:"LastModified"`
			} `xml:"Contents"`
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
		}
		err = xml.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&res)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("S3 list: %w", err)
		}
		for _, o := range res.Contents {
			name := strings.TrimPrefix(o.Key, c.objectKey(""))
			out = append(out, blobInfo{Name: name, Size: o.Size, Modified: o.LastModified})
		}
		if !res.IsTruncated || res.NextContinuationToken == "" {
			return out, nil
		}
		token = res.NextContinuationToken
	}
}

// objectLock reports whether the bucket has Object Lock enabled.
func (c *s3Store) objectLock(ctx context.Context) (bool, error) {
	resp, err := c.do(ctx, http.MethodGet, c.bucketURL(url.Values{"object-lock": {""}}), nil, 0, emptySHA256, nil)
	if err != nil {
		if strings.Contains(err.Error(), "ObjectLockConfigurationNotFound") {
			return false, nil
		}
		return false, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return bytes.Contains(b, []byte("Enabled")), nil
}

// ---- SFTP ----

type sftpStore struct {
	addr, dir string
	cfg       *ssh.ClientConfig
}

// sftpFile closes the SFTP session with the file it reads.
type sftpFile struct {
	*sftp.File
	close func()
}

func (f sftpFile) Close() error {
	err := f.File.Close()
	f.close()
	return err
}

func (c *sftpStore) open(ctx context.Context) (*sftp.Client, func(), error) {
	d := net.Dialer{Timeout: 20 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, nil, err
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, c.addr, c.cfg)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("SFTP: %w", err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	f, err := sftp.NewClient(client)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return f, func() { _ = f.Close(); _ = client.Close() }, nil
}

func (c *sftpStore) Put(ctx context.Context, name, file string) error {
	cl, done, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer done()
	dst := path.Join(c.dir, name)
	if err := cl.MkdirAll(path.Dir(dst)); err != nil {
		return err
	}
	src, err := os.Open(file)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp := path.Join(path.Dir(dst), ".put-"+path.Base(dst))
	w, err := cl.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := cl.PosixRename(tmp, dst); err != nil {
		return cl.Rename(tmp, dst) // servers without the posix-rename extension
	}
	return nil
}

func (c *sftpStore) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	cl, done, err := c.open(ctx)
	if err != nil {
		return nil, err
	}
	f, err := cl.Open(path.Join(c.dir, name))
	if err != nil {
		done()
		return nil, err
	}
	return sftpFile{f, done}, nil
}

func (c *sftpStore) List(ctx context.Context, prefix string) ([]blobInfo, error) {
	cl, done, err := c.open(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	var out []blobInfo
	w := cl.Walk(c.dir)
	for w.Step() {
		if w.Err() != nil {
			if os.IsNotExist(w.Err()) {
				return nil, nil
			}
			return nil, w.Err()
		}
		st := w.Stat()
		rel := strings.TrimPrefix(strings.TrimPrefix(w.Path(), c.dir), "/")
		if st.IsDir() || strings.HasPrefix(path.Base(rel), ".put-") || !strings.HasPrefix(rel, prefix) {
			continue
		}
		out = append(out, blobInfo{Name: rel, Size: st.Size(), Modified: st.ModTime()})
	}
	return out, nil
}

func (c *sftpStore) Delete(ctx context.Context, name string) error {
	cl, done, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer done()
	return cl.Remove(path.Join(c.dir, name))
}

// testStore writes, reads back and deletes a probe object; the result is
// shown next to the target. For S3 it also reports Object Lock.
func testStore(ctx context.Context, st blobStore) (string, error) {
	f, err := os.CreateTemp("", "limdm-probe-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	probe := []byte("limdm storage probe " + time.Now().UTC().Format(time.RFC3339))
	if _, err := f.Write(probe); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	name := ".limdm-probe"
	if err := st.Put(ctx, name, f.Name()); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	rc, err := st.Get(ctx, name)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	got, err := io.ReadAll(io.LimitReader(rc, 1024))
	rc.Close()
	if err != nil || !bytes.Equal(got, probe) {
		return "", errors.New("read back a different content")
	}
	note := "write, read and delete work"
	if err := st.Delete(ctx, name); err != nil {
		note = "write and read work; deleting the probe failed (" + err.Error() + ")"
	}
	if c, ok := st.(*s3Store); ok {
		lock, err := c.objectLock(ctx)
		switch {
		case err != nil:
			note += "; Object Lock status unknown"
		case lock:
			note += "; Object Lock enabled"
		default:
			note += "; Object Lock not enabled on this bucket"
		}
	}
	return note, nil
}

// storeSort orders listings newest first.
func storeSort(l []blobInfo) {
	slices.SortFunc(l, func(a, b blobInfo) int { return b.Modified.Compare(a.Modified) })
}
