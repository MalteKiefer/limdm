package server

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// davStore is a WebDAV folder (Nextcloud, ownCloud, Hetzner Storage Box,
// Apache mod_dav), over https only: PUT streams a file, MKCOL creates the
// folders, PROPFIND lists, DELETE removes. With a user the secret is the
// password (basic auth), without one a bearer token.
type davStore struct {
	base, user, secret string
	client             *http.Client
}

func (d *davStore) url(name string) string {
	var parts []string
	for _, p := range strings.Split(name, "/") {
		if p != "" {
			parts = append(parts, url.PathEscape(p))
		}
	}
	if len(parts) == 0 {
		return d.base
	}
	return d.base + "/" + strings.Join(parts, "/")
}

func (d *davStore) do(ctx context.Context, method, u string, body io.Reader, size int64, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if d.user != "" {
		req.SetBasicAuth(d.user, d.secret)
	} else if d.secret != "" {
		req.Header.Set("Authorization", "Bearer "+d.secret)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		resp.Body.Close()
		return resp, fmt.Errorf("WebDAV %s: %s", method, resp.Status)
	}
	return resp, nil
}

// mkcol creates the folders above name; existing ones answer 405.
func (d *davStore) mkcol(ctx context.Context, name string) error {
	dir := ""
	for _, p := range strings.Split(path.Dir(name), "/") {
		if p == "" || p == "." {
			continue
		}
		dir = path.Join(dir, p)
		resp, err := d.do(ctx, "MKCOL", d.url(dir), nil, 0, nil)
		if err != nil && (resp == nil || resp.StatusCode != http.StatusMethodNotAllowed) {
			return err
		}
		if err == nil {
			resp.Body.Close()
		}
	}
	return nil
}

func (d *davStore) Put(ctx context.Context, name, file string) error {
	if err := d.mkcol(ctx, name); err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	hdr := http.Header{"Content-Type": {"application/octet-stream"}}
	resp, err := d.do(ctx, http.MethodPut, d.url(name), f, st.Size(), hdr)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (d *davStore) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	resp, err := d.do(ctx, http.MethodGet, d.url(name), nil, 0, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (d *davStore) Delete(ctx context.Context, name string) error {
	resp, err := d.do(ctx, http.MethodDelete, d.url(name), nil, 0, nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

const propfindBody = `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getcontentlength/><d:getlastmodified/><d:resourcetype/></d:prop></d:propfind>`

// List reads the folder of prefix (one level, as backups and the probe
// are stored).
func (d *davStore) List(ctx context.Context, prefix string) ([]blobInfo, error) {
	dir := path.Dir(prefix + "x")
	if dir == "." {
		dir = ""
	}
	hdr := http.Header{"Depth": {"1"}, "Content-Type": {"application/xml"}}
	resp, err := d.do(ctx, "PROPFIND", d.url(dir)+"/", strings.NewReader(propfindBody), int64(len(propfindBody)), hdr)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ms struct {
		Responses []struct {
			Href string `xml:"href"`
			Prop struct {
				Length   int64  `xml:"getcontentlength"`
				Modified string `xml:"getlastmodified"`
				Type     struct {
					Collection *struct{} `xml:"collection"`
				} `xml:"resourcetype"`
			} `xml:"propstat>prop"`
		} `xml:"response"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&ms); err != nil {
		return nil, fmt.Errorf("WebDAV list: %w", err)
	}
	var out []blobInfo
	for _, r := range ms.Responses {
		if r.Prop.Type.Collection != nil {
			continue
		}
		href, err := url.PathUnescape(r.Href)
		if err != nil {
			return nil, err
		}
		name := path.Join(dir, path.Base(href))
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		mod, _ := time.Parse(time.RFC1123, r.Prop.Modified)
		out = append(out, blobInfo{Name: name, Size: r.Prop.Length, Modified: mod})
	}
	return out, nil
}
