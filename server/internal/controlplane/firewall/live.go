package firewall

import (
	"fmt"
	"strings"

	"github.com/novusgate/novusgate/internal/netctl/nft"
)

// Live is what the running table shows: rule counters and the sources the
// input policy dropped in the last hour. Both reset when a change is applied
// (the table is replaced).
type Live struct {
	TableLoaded bool
	Counters    []nft.RuleCounter
	Dropped     []nft.DroppedSource
}

// Live reads table inet novusgate from the host. Without the table (iptables
// and shadow modes, or before the first apply) it reports TableLoaded false.
func (e *Engine) Live() (Live, error) {
	r := e.Applier.Exec.Runner
	text, err := r.Run("", "nft", "-a", "list", "table", "inet", nft.TableName)
	if err != nil {
		if strings.Contains(err.Error(), "No such file or directory") {
			return Live{}, nil
		}
		return Live{}, fmt.Errorf("list the nftables table: %w", err)
	}
	js, err := r.Run("", "nft", "-j", "list", "table", "inet", nft.TableName)
	if err != nil {
		return Live{}, fmt.Errorf("list the nftables table as JSON: %w", err)
	}
	dropped, err := nft.ParseDropped([]byte(js))
	if err != nil {
		return Live{}, err
	}
	return Live{TableLoaded: true, Counters: nft.ParseCounters(text), Dropped: dropped}, nil
}
