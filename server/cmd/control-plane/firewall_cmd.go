package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/spf13/cobra"
)

var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Inspect the nftables firewall engine",
}

var firewallPreviewCmd = &cobra.Command{
	Use:   "preview",
	Short: "Print the nftables ruleset compiled from the database (changes nothing)",
	RunE:  runFirewallPreview,
}

func init() {
	firewallPreviewCmd.Flags().String("database", "", "Database connection string")
	firewallPreviewCmd.Flags().Bool("check", false, "Also validate the ruleset with nft -c (needs nft and CAP_NET_ADMIN)")
	firewallCmd.AddCommand(firewallPreviewCmd)
	rootCmd.AddCommand(firewallCmd)
}

func runFirewallPreview(cmd *cobra.Command, args []string) error {
	databaseURL, _ := cmd.Flags().GetString("database")
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		return fmt.Errorf("database connection string is required (--database or DATABASE_URL)")
	}
	db, err := store.New(databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	runner := nft.HostRunner{}
	sshPorts, egress, err := firewall.DetectHost(runner)
	if err != nil {
		return fmt.Errorf("host detection failed: %w", err)
	}
	rs, warnings, err := firewall.BuildRuleset(context.Background(), db, sshPorts, egress)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	script, err := nft.Compile(rs, time.Now())
	if err != nil {
		return err
	}
	fmt.Print(script)

	if check, _ := cmd.Flags().GetBool("check"); check {
		// The host's nft, like the engine: the container's may not match the kernel.
		if err := (nft.Executor{Runner: nft.NsenterRunner{}}).Check(script); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "nft -c: OK")
	}
	return nil
}
