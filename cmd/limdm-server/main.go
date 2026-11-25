// limdm-server runs the management server, or creates release signing keys and
// signed agent release manifests.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
	"github.com/maltekiefer/limdm/internal/server"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "keygen":
		err = keygen(os.Args[2:])
	case "release":
		err = release(os.Args[2:])
	case "local-admin":
		err = localAdmin(os.Args[2:])
	default:
		err = errors.New(`usage: limdm-server [serve | keygen -out FILE | release -key FILE -version V -dir DIR ARCH=BINARY...
                     | local-admin [-env FILE] [-role admin|auditor] [-out FILE] add|reset|disable|enable|list [NAME]]`)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(log *slog.Logger) error {
	cfg, err := server.ConfigFromEnv()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv, err := server.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer srv.Close()
	srv.Background(ctx)
	agentTLS, err := srv.AgentTLSConfig()
	if err != nil {
		return err
	}
	newServer := func(addr string, h http.Handler, tc *tls.Config) *http.Server {
		return &http.Server{
			Addr: addr, Handler: h, TLSConfig: tc,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 120 * time.Second,
		}
	}
	admin := newServer(cfg.Listen, srv.AdminHandler(), &tls.Config{MinVersion: tls.VersionTLS12})
	agent := newServer(cfg.AgentListen, srv.AgentHandler(), agentTLS)

	errc := make(chan error, 2)
	go func() {
		log.Info("admin UI listening", "addr", cfg.Listen, "tls", cfg.TLSCert != "")
		if cfg.TLSCert != "" {
			errc <- admin.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- admin.ListenAndServe() // loopback only, enforced in config
		}
	}()
	go func() {
		log.Info("agent API listening (mTLS, TLS 1.3)", "addr", cfg.AgentListen)
		errc <- agent.ListenAndServeTLS("", "")
	}()
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = errors.Join(err, admin.Shutdown(sctx), agent.Shutdown(sctx))
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// localAdmin manages fallback admin accounts. Generated credentials go to
// stdout or, with -out, to a new 0600 file so they do not end up in logs.
func localAdmin(args []string) error {
	fs := flag.NewFlagSet("local-admin", flag.ExitOnError)
	envFile := fs.String("env", "", "read LIMDM_* settings from this env file (e.g. /etc/limdm-server/server.env)")
	role := fs.String("role", "admin", "admin or auditor")
	out := fs.String("out", "", "write generated credentials to this new file (mode 0600)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return errors.New("need an operation: add, reset, disable, enable or list")
	}
	if *envFile != "" {
		if err := loadEnvFile(*envFile); err != nil {
			return err
		}
	}
	dsn := os.Getenv("LIMDM_DATABASE_URL")
	if dsn == "" {
		return errors.New("LIMDM_DATABASE_URL not set (use -env)")
	}
	res, err := server.LocalAdmin(context.Background(), dsn, fs.Arg(0), fs.Arg(1), *role)
	if err != nil || res == "" {
		return err
	}
	if *out == "" {
		fmt.Print(res)
		return nil
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(res); err != nil {
		f.Close()
		return err
	}
	fmt.Println("credentials written to", *out)
	return f.Close()
}

// loadEnvFile applies KEY=VALUE lines (systemd EnvironmentFile syntax subset).
func loadEnvFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			if err := os.Setenv(strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)); err != nil {
				return err
			}
		}
	}
	return nil
}

// keygen writes the private release key (keep it offline) and prints the public
// key to compile into the agent.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "release.key", "private key file")
	fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return err
	}
	fmt.Printf("private key: %s\npublic key (build agent with UPDATE_PUBKEY=...): %s\n", *out, hex.EncodeToString(pub))
	return nil
}

// release copies agent binaries into the release dir and writes a signed manifest.
func release(args []string) error {
	fs := flag.NewFlagSet("release", flag.ExitOnError)
	keyFile := fs.String("key", "release.key", "private key file")
	version := fs.String("version", "", "agent version, e.g. 1.2.0")
	dir := fs.String("dir", "", "release dir (LIMDM_RELEASE_DIR of the server)")
	fs.Parse(args)
	if *version == "" || *dir == "" || fs.NArg() == 0 {
		return errors.New("need -version, -dir and ARCH=BINARY arguments")
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid private key")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil { //nolint:gosec // served read only by the server
		return err
	}
	var rels []api.Release
	for _, a := range fs.Args() {
		arch, bin, ok := strings.Cut(a, "=")
		if !ok {
			return fmt.Errorf("argument %q is not ARCH=BINARY", a)
		}
		name := fmt.Sprintf("limdm-agent-%s-%s", *version, arch)
		sum, err := copyHash(bin, filepath.Join(*dir, name))
		if err != nil {
			return err
		}
		r := api.Release{Version: *version, Arch: arch, File: name, SHA256: sum}
		r.Sig = hex.EncodeToString(ed25519.Sign(key, r.SignedBytes()))
		rels = append(rels, r)
	}
	b, _ := json.MarshalIndent(rels, "", "  ")
	tmp := filepath.Join(*dir, ".manifest.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil { //nolint:gosec // public signed manifest
		return err
	}
	return os.Rename(tmp, filepath.Join(*dir, "manifest.json"))
}

func copyHash(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) //nolint:gosec // public signed binary
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), out.Close()
}
