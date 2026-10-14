package rest

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/backup"
)

func newBackupServer(t *testing.T) *Server {
	t.Helper()
	s, _, _ := newContractServer(t)
	root := t.TempDir()
	wg := filepath.Join(root, "wg")
	os.MkdirAll(wg, 0o700)
	os.WriteFile(filepath.Join(wg, "wg0.conf"), []byte("[Interface]\n"), 0o600)
	clock := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	s.SetBackups(&backup.Service{
		Dir:          filepath.Join(root, "backups"),
		WireGuardDir: wg,
		Dump:         func(_ context.Context, w io.Writer) error { _, err := io.WriteString(w, "-- dump\n"); return err },
		Now:          func() time.Time { clock = clock.Add(time.Minute); return clock },
	})
	return s
}

func TestBackupsCreateListDownloadDelete(t *testing.T) {
	s := newBackupServer(t)

	rec := callAs(t, s, "POST", "/api/v1/backups", "", true)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created backup.Info
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Name != "novusgate-backup-20261015-090100.tar.gz" || created.Size == 0 {
		t.Fatalf("created = %+v", created)
	}
	assertMatchesSpec(t, s, "POST", "/api/v1/backups", rec)

	list := callAs(t, s, "GET", "/api/v1/backups", "", true)
	if list.Code != 200 || !strings.Contains(list.Body.String(), created.Name) {
		t.Fatalf("list = %d %s", list.Code, list.Body)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/backups", list)

	dl := callAs(t, s, "GET", "/api/v1/backups/"+created.Name, "", true)
	if dl.Code != 200 || dl.Header().Get("Content-Type") != "application/gzip" ||
		!strings.Contains(dl.Header().Get("Content-Disposition"), created.Name) || dl.Body.Len() != int(created.Size) {
		t.Fatalf("download = %d %v len %d", dl.Code, dl.Header(), dl.Body.Len())
	}

	if del := callAs(t, s, "DELETE", "/api/v1/backups/"+created.Name, "", true); del.Code != 204 {
		t.Fatalf("delete = %d %s", del.Code, del.Body)
	}
	if again := callAs(t, s, "DELETE", "/api/v1/backups/"+created.Name, "", true); again.Code != 404 {
		t.Fatalf("delete again = %d, want 404", again.Code)
	}
	// The router cleans a path with ../ (301) before any handler runs.
	if bad := callAs(t, s, "GET", "/api/v1/backups/..%2F..%2Fetc%2Fpasswd", "", true); bad.Code == 200 {
		t.Fatalf("traversal = 200 %s", bad.Body)
	}
	// A name that is not a backup file name never reaches the disk.
	if bad := callAs(t, s, "GET", "/api/v1/backups/wg0.conf", "", true); bad.Code != 404 {
		t.Fatalf("other file = %d, want 404", bad.Code)
	}
}

func TestBackupsNeedSessionAndConfiguration(t *testing.T) {
	s := newBackupServer(t)
	if rec := callAs(t, s, "GET", "/api/v1/backups", "", false); rec.Code != 401 {
		t.Fatalf("anonymous list = %d, want 401", rec.Code)
	}
	plain, _, _ := newContractServer(t) // no backup service
	if rec := callAs(t, plain, "POST", "/api/v1/backups", "", true); rec.Code != 503 {
		t.Fatalf("unconfigured = %d, want 503", rec.Code)
	}
}
