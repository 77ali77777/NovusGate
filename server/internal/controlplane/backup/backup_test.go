package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newService(t *testing.T) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	wg := filepath.Join(root, "wireguard")
	if err := os.MkdirAll(wg, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(wg, "wg0.conf"), []byte("[Interface]\nPrivateKey = K\n"), 0o600)
	os.WriteFile(filepath.Join(wg, "wg1.conf"), []byte("[Interface]\n"), 0o600)
	clock := time.Date(2026, 10, 15, 9, 30, 0, 0, time.UTC)
	return &Service{
		Dir:          filepath.Join(root, "backups"),
		WireGuardDir: wg,
		Dump: func(_ context.Context, w io.Writer) error {
			_, err := io.WriteString(w, "-- dump\nCREATE TABLE x();\n")
			return err
		},
		Now: func() time.Time { clock = clock.Add(time.Second); return clock },
	}, root
}

func readArchive(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
	}
}

func TestCreateWritesDumpAndWireGuardConfigs(t *testing.T) {
	s, _ := newService(t)
	info, err := s.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "novusgate-backup-20261015-093001.tar.gz" || info.Size == 0 {
		t.Fatalf("info = %+v", info)
	}
	files := readArchive(t, filepath.Join(s.Dir, info.Name))
	if files["db.sql"] != "-- dump\nCREATE TABLE x();\n" || files["wireguard/wg0.conf"] == "" || files["wireguard/wg1.conf"] == "" {
		t.Fatalf("archive = %v", files)
	}
	st, _ := os.Stat(filepath.Join(s.Dir, info.Name))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v: it holds private keys", st.Mode().Perm())
	}
	dir, _ := os.Stat(s.Dir)
	if dir.Mode().Perm() != 0o700 {
		t.Fatalf("backup dir mode %v", dir.Mode().Perm())
	}
}

func TestFailedDumpLeavesNoFile(t *testing.T) {
	s, _ := newService(t)
	s.Dump = func(context.Context, io.Writer) error { return errors.New("pg_dump: connection refused") }
	if _, err := s.Create(context.Background()); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v", err)
	}
	entries, _ := os.ReadDir(s.Dir)
	if len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

func TestListNewestFirstOpenAndDelete(t *testing.T) {
	s, _ := newService(t)
	a, _ := s.Create(context.Background())
	b, _ := s.Create(context.Background())
	os.WriteFile(filepath.Join(s.Dir, "notes.txt"), []byte("x"), 0o600) // not a backup
	list, err := s.List()
	if err != nil || len(list) != 2 || list[0].Name != b.Name || list[1].Name != a.Name {
		t.Fatalf("list = %+v, %v", list, err)
	}
	f, info, err := s.Open(a.Name)
	if err != nil || info.Name != a.Name {
		t.Fatalf("open = %v, %v", info, err)
	}
	f.Close()
	if err := s.Delete(a.Name); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Open(a.Name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("open after delete = %v", err)
	}
}

// Names come from the URL: anything but a backup file name is refused,
// so no other file can be read or deleted.
func TestNamesAreValidated(t *testing.T) {
	s, root := newService(t)
	os.MkdirAll(s.Dir, 0o700)
	for _, name := range []string{"../wireguard/wg0.conf", "novusgate-backup-x.tar.gz", "/etc/passwd", "notes.txt", ""} {
		if _, _, err := s.Open(name); !errors.Is(err, ErrNotFound) {
			t.Errorf("open %q = %v, want ErrNotFound", name, err)
		}
		if err := s.Delete(name); !errors.Is(err, ErrNotFound) {
			t.Errorf("delete %q = %v, want ErrNotFound", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "wireguard", "wg0.conf")); err != nil {
		t.Fatal("a refused name must not touch other files")
	}
}

func TestOneBackupAtATime(t *testing.T) {
	s, _ := newService(t)
	release := make(chan struct{})
	started := make(chan struct{})
	s.Dump = func(_ context.Context, w io.Writer) error {
		close(started)
		<-release
		return nil
	}
	done := make(chan error)
	go func() { _, err := s.Create(context.Background()); done <- err }()
	<-started
	if _, err := s.Create(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("second Create = %v, want ErrBusy", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
