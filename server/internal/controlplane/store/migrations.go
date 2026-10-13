package store

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

//go:embed migrations_sql/*.sql
var migrationFS embed.FS

// Migrate runs database migrations (only new ones)
func (s *Store) Migrate(ctx context.Context) error {
	// 1. Create migration tracking table if not exists
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// 2. Get list of already applied migrations
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("failed to query schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return err
		}
		applied[version] = true
	}

	// 3. Read migration files
	entries, err := migrationFS.ReadDir("migrations_sql")
	if err != nil {
		return fmt.Errorf("failed to read migrations: %w", err)
	}

	var filenames []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			filenames = append(filenames, entry.Name())
		}
	}
	sort.Strings(filenames)

	// 4. Apply only new migrations
	newCount := 0
	for _, filename := range filenames {
		if applied[filename] {
			slog.Info(fmt.Sprintf("Skipping (already applied): %s", filename))
			continue
		}

		content, err := migrationFS.ReadFile("migrations_sql/" + filename)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", filename, err)
		}

		slog.Info(fmt.Sprintf("Applying migration: %s", filename))
		if _, err := s.db.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", filename, err)
		}

		// Record as applied
		_, err = s.db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, filename)
		if err != nil {
			return fmt.Errorf("failed to record migration %s: %w", filename, err)
		}
		newCount++
	}

	if newCount == 0 {
		slog.Info("Database is up to date, no new migrations.")
	} else {
		slog.Info(fmt.Sprintf("Applied %d new migration(s).", newCount))
	}

	return nil
}
