package backup

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestPgDumpAgainstDatabase runs the real pg_dump. It needs TEST_DATABASE_URL
// and a pg_dump of the server's major version (the control-plane image has
// postgresql16-client); it is skipped otherwise.
func TestPgDumpAgainstDatabase(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL")
	}
	if _, err := exec.LookPath("pg_dump"); err != nil {
		t.Skip("pg_dump not installed")
	}
	var out bytes.Buffer
	if err := PgDump(url)(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "PostgreSQL database dump") {
		t.Fatalf("not a dump:\n%.300s", out.String())
	}

	bad := PgDump("postgres://nobody:wrong@127.0.0.1:1/none?sslmode=disable")
	if err := bad(context.Background(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "exit status") {
		t.Fatalf("a failing pg_dump = %v, want its exit status", err)
	}
}
