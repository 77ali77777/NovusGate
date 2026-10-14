// Package backup makes manual backups from the panel (P8): one tar.gz with
// the database dump and the WireGuard configs. Restore is manual
// (docs/deployment.md).
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

var (
	// ErrNotFound: no backup with that name (or the name is not one).
	ErrNotFound = errors.New("backup not found")
	// ErrBusy: another backup is being made.
	ErrBusy = errors.New("a backup is already running")
)

// nameRe is the only file name Open and Delete accept, so a name from the
// URL can never reach another file.
var nameRe = regexp.MustCompile(`^novusgate-backup-\d{8}-\d{6}\.tar\.gz$`)

// Info describes a backup file.
type Info struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// Service makes and lists backups in Dir. Dump writes the database dump.
type Service struct {
	Dir          string
	WireGuardDir string
	Dump         func(ctx context.Context, w io.Writer) error
	Now          func() time.Time
	mu           sync.Mutex
	running      bool
}

// Create writes a new backup; the file appears only when it is complete.
// It holds private keys: the directory is 0700 and the file 0600.
func (s *Service) Create(ctx context.Context) (Info, error) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return Info{}, ErrBusy
	}
	s.running = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()

	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return Info{}, err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return Info{}, err
	}
	name := "novusgate-backup-" + s.Now().UTC().Format("20060102-150405") + ".tar.gz"
	tmp, err := os.CreateTemp(s.Dir, ".partial-*")
	if err != nil {
		return Info{}, err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return Info{}, err
	}
	if err := s.write(ctx, tmp); err != nil {
		tmp.Close()
		return Info{}, err
	}
	if err := tmp.Close(); err != nil {
		return Info{}, err
	}
	final := filepath.Join(s.Dir, name)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return Info{}, err
	}
	return stat(final)
}

func (s *Service) write(ctx context.Context, f *os.File) error {
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	// The dump goes through a temp file: tar needs the size up front.
	dump, err := os.CreateTemp(s.Dir, ".dump-*")
	if err != nil {
		return err
	}
	defer os.Remove(dump.Name())
	defer dump.Close()
	if err := s.Dump(ctx, dump); err != nil {
		return fmt.Errorf("database dump: %w", err)
	}
	if err := addFile(tw, dump.Name(), "db.sql"); err != nil {
		return err
	}

	entries, err := os.ReadDir(s.WireGuardDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			if err := addFile(tw, filepath.Join(s.WireGuardDir, e.Name()), "wireguard/"+e.Name()); err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func addFile(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// List returns the backups, newest first.
func (s *Service) List() ([]Info, error) {
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return []Info{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Info{}
	for _, e := range entries {
		if !nameRe.MatchString(e.Name()) {
			continue
		}
		info, err := stat(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name }) // the name holds the time
	return out, nil
}

// Open returns a backup for download.
func (s *Service) Open(name string) (*os.File, Info, error) {
	if !nameRe.MatchString(name) {
		return nil, Info{}, ErrNotFound
	}
	path := filepath.Join(s.Dir, name)
	info, err := stat(path)
	if err != nil {
		return nil, Info{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, Info{}, err
	}
	return f, info, nil
}

// Delete removes a backup.
func (s *Service) Delete(name string) error {
	if !nameRe.MatchString(name) {
		return ErrNotFound
	}
	err := os.Remove(filepath.Join(s.Dir, name))
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	return err
}

func stat(path string) (Info, error) {
	st, err := os.Stat(path)
	if os.IsNotExist(err) {
		return Info{}, ErrNotFound
	}
	if err != nil {
		return Info{}, err
	}
	return Info{Name: filepath.Base(path), Size: st.Size(), CreatedAt: st.ModTime().UTC()}, nil
}

// PgDump returns a Dump that runs pg_dump against databaseURL.
func PgDump(databaseURL string) func(ctx context.Context, w io.Writer) error {
	return func(ctx context.Context, w io.Writer) error {
		cmd := exec.CommandContext(ctx, "pg_dump", "--no-owner", "--no-privileges", "--dbname="+databaseURL)
		cmd.Stdout = w
		var stderr limitedBuffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%w: %s", err, stderr.String())
		}
		return nil
	}
}

// limitedBuffer keeps the first 2 KiB of pg_dump's errors.
type limitedBuffer struct{ b []byte }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := 2048 - len(l.b); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.b = append(l.b, p[:room]...)
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return string(l.b) }
