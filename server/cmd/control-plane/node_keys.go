package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/secretbox"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var keysToLabelsCmd = &cobra.Command{
	Use:   "keys-to-labels",
	Short: "Write node private keys back into labels (before rolling back below P4c)",
	RunE:  runKeysToLabels,
}

// setupNodeKeys loads the master key and moves node private keys out of
// labels into the sealed column (re-sealing plain ones once a key is set).
// An invalid master key stops the server; a missing one only warns.
func setupNodeKeys(ctx context.Context, db *store.Store) error {
	box, err := secretbox.FromEnv()
	if err != nil {
		return err
	}
	if box == nil {
		slog.Warn(fmt.Sprintf("%s is not set: node private keys are stored unencrypted", secretbox.EnvVar))
	}
	db.SetKeyBox(box)
	if err := db.CheckNodeKeys(ctx); err != nil {
		return err
	}
	moved, resealed, err := db.MigrateNodeKeys(ctx)
	if err != nil {
		return fmt.Errorf("migrate node keys: %w", err)
	}
	if moved > 0 || resealed > 0 {
		slog.Info(fmt.Sprintf("Node keys: %d moved out of labels, %d encrypted", moved, resealed))
	}
	return nil
}

func runKeysToLabels(cmd *cobra.Command, args []string) error {
	databaseURL := viper.GetString("database_url")
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		return fmt.Errorf("database connection string is required")
	}
	db, err := store.New(databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()
	box, err := secretbox.FromEnv()
	if err != nil {
		return err
	}
	db.SetKeyBox(box)
	n, err := db.RestoreNodeKeysToLabels(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %d node keys back into labels\n", n)
	return nil
}
