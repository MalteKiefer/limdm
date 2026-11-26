package server

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// roundTrip puts a file, reads it back, lists and deletes it.
func roundTrip(t *testing.T, st blobStore, name string, content []byte) {
	t.Helper()
	ctx := context.Background()
	f := filepath.Join(t.TempDir(), "in")
	os.WriteFile(f, content, 0o600)
	if err := st.Put(ctx, name, f); err != nil {
		t.Fatal(err)
	}
	rc, err := st.Get(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, content) {
		t.Fatalf("read back %d bytes, want %d", len(got), len(content))
	}
	list, err := st.List(ctx, "")
	if err != nil || len(list) != 1 || list[0].Name != name || list[0].Size != int64(len(content)) {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := st.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.List(ctx, ""); len(list) != 0 {
		t.Fatalf("deleted object still listed: %+v", list)
	}
	if _, err := testStore(ctx, st); err != nil {
		t.Fatal(err)
	}
}

// fakeDAV is an in memory WebDAV server with the methods the client uses.
func fakeDAV(token string) *httptest.Server {
	var mu sync.Mutex
	files, dirs := map[string][]byte{}, map[string]bool{"/dav": true}
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		p := strings.TrimSuffix(r.URL.Path, "/")
		switch r.Method {
		case "MKCOL":
			if dirs[p] {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			dirs[p] = true
			w.WriteHeader(http.StatusCreated)
		case http.MethodPut:
			if !dirs[filepath.Dir(p)] {
				w.WriteHeader(http.StatusConflict)
				return
			}
			files[p], _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			b, ok := files[p]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(b)
		case http.MethodDelete:
			delete(files, p)
			w.WriteHeader(http.StatusNoContent)
		case "PROPFIND":
			if r.Header.Get("Depth") != "1" || !dirs[p] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(207)
			fmt.Fprintf(w, `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>%s/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>`, p)
			for name, b := range files {
				if filepath.Dir(name) == p {
					fmt.Fprintf(w, `<d:response><d:href>%s</d:href><d:propstat><d:prop><d:getcontentlength>%d</d:getcontentlength><d:getlastmodified>%s</d:getlastmodified><d:resourcetype/></d:prop></d:propstat></d:response>`,
						strings.ReplaceAll(name, " ", "%20"), len(b), time.Now().UTC().Format(time.RFC1123))
				}
			}
			fmt.Fprint(w, `</d:multistatus>`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}

func TestWebDAVStore(t *testing.T) {
	srv := fakeDAV("tok")
	defer srv.Close()
	st := &davStore{base: srv.URL + "/dav", secret: "tok", client: srv.Client()}
	roundTrip(t, st, "limdm-mdm.test-20261126T020000Z.lbk", bytes.Repeat([]byte("x"), 70000))
	if err := (StoreTarget{Name: "nc", Kind: "webdav", Endpoint: "http://cloud.test/dav"}).validate(); err == nil {
		t.Fatal("plain http WebDAV accepted")
	}
}

// fakeS3 keeps objects in memory and supports multipart uploads; it checks
// that every request is signed and every body matches its Content-MD5.
func fakeS3() (*httptest.Server, *int) {
	var mu sync.Mutex
	objects, uploads := map[string][]byte{}, map[string]map[int][]byte{}
	multipart := 0
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=keyid/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if m := r.Header.Get("Content-MD5"); m != "" {
			sum := md5.Sum(body)
			if m != base64.StdEncoding.EncodeToString(sum[:]) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		key, q := r.URL.Path, r.URL.Query()
		switch {
		case r.Method == http.MethodGet && q.Get("list-type") == "2":
			fmt.Fprint(w, `<ListBucketResult>`)
			var keys []string
			for k := range objects {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if strings.HasPrefix(k, "/bucket/"+q.Get("prefix")) {
					fmt.Fprintf(w, `<Contents><Key>%s</Key><Size>%d</Size><LastModified>2026-11-26T02:00:00Z</LastModified></Contents>`, strings.TrimPrefix(k, "/bucket/"), len(objects[k]))
				}
			}
			fmt.Fprint(w, `<IsTruncated>false</IsTruncated></ListBucketResult>`)
		case r.Method == http.MethodGet && q.Has("object-lock"):
			fmt.Fprint(w, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
		case r.Method == http.MethodPost && q.Has("uploads"):
			if r.Header.Get("x-amz-object-lock-mode") != "COMPLIANCE" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			uploads["u1"] = map[int][]byte{}
			fmt.Fprint(w, `<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodPut && q.Get("uploadId") != "":
			var n int
			fmt.Sscan(q.Get("partNumber"), &n)
			uploads[q.Get("uploadId")][n] = body
			w.Header().Set("ETag", fmt.Sprintf(`"p%d"`, n))
		case r.Method == http.MethodPost && q.Get("uploadId") != "":
			parts := uploads[q.Get("uploadId")]
			var all []byte
			for i := 1; i <= len(parts); i++ {
				if !strings.Contains(strings.ReplaceAll(string(body), "&#34;", `"`), fmt.Sprintf(`<PartNumber>%d</PartNumber><ETag>"p%d"</ETag>`, i, i)) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				all = append(all, parts[i]...)
			}
			objects[key] = all
			multipart++
			fmt.Fprint(w, `<CompleteMultipartUploadResult/>`)
		case r.Method == http.MethodPut:
			objects[key] = body
		case r.Method == http.MethodGet:
			b, ok := objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(b)
		case r.Method == http.MethodDelete:
			delete(objects, key)
			w.WriteHeader(http.StatusNoContent)
		}
	})), &multipart
}

// TestB2Store runs the B2 target (Backblaze's S3 API) against a fake: a
// large archive goes up in parts with the file lock set on creation.
func TestB2Store(t *testing.T) {
	srv, multipart := fakeS3()
	defer srv.Close()
	s := &Server{cfg: Config{SessionKey: bytes.Repeat([]byte{7}, 32)}}
	sealed, _ := s.sealField("store.b2.secret", "appkey")
	target := StoreTarget{Name: "b2", Kind: "b2", Region: "eu-central-003", Bucket: "bucket", AccessKey: "keyid", SecretEnc: sealed, LockMode: "COMPLIANCE", LockDays: 30}
	if err := target.validate(); err != nil {
		t.Fatal(err)
	}
	st, err := s.openStore(target)
	if err != nil {
		t.Fatal(err)
	}
	c := st.(*s3Store)
	if c.endpoint != "https://s3.eu-central-003.backblazeb2.com" || !c.pathStyle || c.secret != "appkey" {
		t.Fatalf("b2 endpoint %s", c.endpoint)
	}
	c.endpoint, c.client = srv.URL, srv.Client()
	defer func(n int64) { s3PartSize = n }(s3PartSize)
	s3PartSize = 1000
	roundTrip(t, c, "limdm-mdm.test-20261126T020000Z.lbk", bytes.Repeat([]byte("0123456789"), 350))
	if *multipart != 1 {
		t.Fatalf("multipart uploads: %d", *multipart)
	}
}

func TestStoreClientNoRedirect(t *testing.T) {
	followed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/other" {
			followed = true
			return
		}
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer srv.Close()
	resp, err := storeClient().Get(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if followed || resp.StatusCode != http.StatusFound {
		t.Fatal("store client followed a redirect")
	}
}
