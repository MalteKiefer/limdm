// Command e2eseed runs a SQL file against the end to end test database
// (LIMDM_E2E_DATABASE_URL), so the console app tests have devices to show.
// It refuses a database whose name does not contain "e2e".
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "e2eseed:", err)
		os.Exit(1)
	}
}

func run() error {
	dsn := os.Getenv("LIMDM_E2E_DATABASE_URL")
	u, err := url.Parse(dsn)
	if err != nil || !strings.Contains(u.Path, "e2e") {
		return fmt.Errorf("LIMDM_E2E_DATABASE_URL must name a database containing e2e")
	}
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: e2eseed <file.sql>")
	}
	sql, err := os.ReadFile(os.Args[1]) //nolint:gosec // a test helper reads the file its caller names
	if err != nil {
		return err
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close(ctx) }()
	_, err = c.Exec(ctx, string(sql))
	return err
}
