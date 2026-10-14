package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/shared/secretbox"
)

const testMasterKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// keyNode creates a network and a node for key tests; labels may carry a
// legacy private key.
func keyNode(t *testing.T, s *Store, labels map[string]string) *models.Node {
	t.Helper()
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM networks WHERE name = 'keys-net'")
	nw := &models.Network{Name: "keys-net", CIDR: "10.72.0.0/24", ListenPort: 51872, InterfaceName: "wg72"}
	if err := s.CreateNetwork(ctx, nw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), nw.ID) })
	n := &models.Node{NetworkID: nw.ID, Name: "keys-node", VirtualIP: net.ParseIP("10.72.0.2"),
		PublicKey: strings.Repeat("K", 43) + "=", Labels: labels, Status: models.NodeStatusOnline}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	return n
}

func storedKey(t *testing.T, s *Store, nodeID string) string {
	t.Helper()
	var v *string
	s.db.QueryRowContext(context.Background(), "SELECT private_key_enc FROM nodes WHERE id = $1", nodeID).Scan(&v)
	if v == nil {
		return ""
	}
	return *v
}

func TestNodePrivateKeyIsSealed(t *testing.T) {
	s := newTestStore(t)
	box, _ := secretbox.New(testMasterKey)
	s.SetKeyBox(box)
	ctx := context.Background()
	n := keyNode(t, s, map[string]string{})
	if got, _ := s.GetNode(ctx, n.ID); got.HasConfig {
		t.Fatal("a node without a key has no config")
	}
	if err := s.SetNodePrivateKey(ctx, n.ID, "node-secret-key"); err != nil {
		t.Fatal(err)
	}
	if raw := storedKey(t, s, n.ID); !strings.HasPrefix(raw, "v2:") || strings.Contains(raw, "node-secret-key") {
		t.Fatalf("stored = %q, want a v2 ciphertext", raw)
	}
	if got, err := s.NodePrivateKey(ctx, n.ID); err != nil || got != "node-secret-key" {
		t.Fatalf("NodePrivateKey = %q, %v", got, err)
	}
	if got, _ := s.GetNode(ctx, n.ID); !got.HasConfig {
		t.Fatal("GetNode must report has_config")
	}
	nodes, _ := s.ListNodes(ctx, n.NetworkID)
	if len(nodes) != 1 || !nodes[0].HasConfig {
		t.Fatalf("ListNodes has_config = %+v", nodes)
	}
}

func TestMigrateNodeKeysIdempotent(t *testing.T) {
	s := newTestStore(t)
	box, _ := secretbox.New(testMasterKey)
	s.SetKeyBox(box)
	ctx := context.Background()
	n := keyNode(t, s, map[string]string{"wireguard_private_key": "legacy-key", "type": "client"})
	moved, _, err := s.MigrateNodeKeys(ctx)
	if err != nil || moved < 1 {
		t.Fatalf("migrate = %d, %v", moved, err)
	}
	got, _ := s.GetNode(ctx, n.ID)
	if _, ok := got.Labels["wireguard_private_key"]; ok || got.Labels["type"] != "client" {
		t.Fatalf("labels after migrate = %v", got.Labels)
	}
	if key, _ := s.NodePrivateKey(ctx, n.ID); key != "legacy-key" {
		t.Fatalf("key after migrate = %q", key)
	}
	if moved, resealed, err := s.MigrateNodeKeys(ctx); err != nil || moved != 0 || resealed != 0 {
		t.Fatalf("second migrate = %d, %d, %v; want 0, 0", moved, resealed, err)
	}
}

func TestMigrateNodeKeysResealsPlain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	n := keyNode(t, s, map[string]string{"wireguard_private_key": "legacy-key"})
	if _, _, err := s.MigrateNodeKeys(ctx); err != nil { // no master key yet
		t.Fatal(err)
	}
	if raw := storedKey(t, s, n.ID); raw != "plain:legacy-key" {
		t.Fatalf("without a key = %q", raw)
	}
	box, _ := secretbox.New(testMasterKey)
	s.SetKeyBox(box)
	_, resealed, err := s.MigrateNodeKeys(ctx)
	if err != nil || resealed < 1 {
		t.Fatalf("reseal = %d, %v", resealed, err)
	}
	if raw := storedKey(t, s, n.ID); !strings.HasPrefix(raw, "v2:") {
		t.Fatalf("after reseal = %q", raw)
	}
	if key, _ := s.NodePrivateKey(ctx, n.ID); key != "legacy-key" {
		t.Fatalf("key after reseal = %q", key)
	}
}

func TestRestoreNodeKeysToLabels(t *testing.T) {
	s := newTestStore(t)
	box, _ := secretbox.New(testMasterKey)
	s.SetKeyBox(box)
	ctx := context.Background()
	n := keyNode(t, s, map[string]string{})
	s.SetNodePrivateKey(ctx, n.ID, "node-secret-key")
	if count, err := s.RestoreNodeKeysToLabels(ctx); err != nil || count < 1 {
		t.Fatalf("restore = %d, %v", count, err)
	}
	got, _ := s.GetNode(ctx, n.ID)
	if got.Labels["wireguard_private_key"] != "node-secret-key" {
		t.Fatalf("labels after restore = %v", got.Labels)
	}
}

func TestAuditUserSetNullOnDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM users WHERE username = 'audit-user'")
	u := &models.User{Username: "audit-user", PasswordHash: "x"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirewallAuditLog(ctx, "audit_test", map[string]interface{}{"k": "v"}, "203.0.113.4", u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirewallAuditLog(ctx, "audit_test_anon", nil, "203.0.113.4", ""); err != nil {
		t.Fatal(err)
	}
	var userID *string
	s.db.QueryRowContext(ctx, "SELECT user_id FROM firewall_audit_log WHERE action = 'audit_test' ORDER BY created_at DESC LIMIT 1").Scan(&userID)
	if userID == nil || *userID != u.ID {
		t.Fatalf("user_id = %v, want %s", userID, u.ID)
	}
	s.DeleteUser(ctx, u.ID)
	var n int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM firewall_audit_log WHERE action = 'audit_test' AND user_id IS NULL").Scan(&n)
	if n < 1 {
		t.Fatal("deleting the user must keep the entry with user_id NULL")
	}
	s.db.ExecContext(ctx, "DELETE FROM firewall_audit_log WHERE action LIKE 'audit_test%'")
}

// A label planted on a node that already has a sealed key must not replace it.
func TestMigrateNodeKeysKeepsExistingKey(t *testing.T) {
	s := newTestStore(t)
	box, _ := secretbox.New(testMasterKey)
	s.SetKeyBox(box)
	ctx := context.Background()
	n := keyNode(t, s, map[string]string{})
	s.SetNodePrivateKey(ctx, n.ID, "real-key")
	s.db.ExecContext(ctx, `UPDATE nodes SET labels = '{"wireguard_private_key":"junk"}' WHERE id = $1`, n.ID)
	if _, _, err := s.MigrateNodeKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if key, _ := s.NodePrivateKey(ctx, n.ID); key != "real-key" {
		t.Fatalf("key = %q, want the real key kept", key)
	}
	if got, _ := s.GetNode(ctx, n.ID); got.Labels["wireguard_private_key"] != "" {
		t.Fatalf("the planted label must be removed: %v", got.Labels)
	}
}

// Startup must notice a master key that cannot open the stored keys.
func TestCheckNodeKeys(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.db.ExecContext(ctx, "UPDATE nodes SET private_key_enc = NULL")
	if err := s.CheckNodeKeys(ctx); err != nil {
		t.Fatalf("no sealed keys = %v", err)
	}
	box, _ := secretbox.New(testMasterKey)
	s.SetKeyBox(box)
	n := keyNode(t, s, map[string]string{})
	s.SetNodePrivateKey(ctx, n.ID, "real-key")
	if err := s.CheckNodeKeys(ctx); err != nil {
		t.Fatalf("right key = %v", err)
	}
	other, _ := secretbox.New(strings.Repeat("ab", 32))
	s.SetKeyBox(other)
	if err := s.CheckNodeKeys(ctx); err == nil {
		t.Fatal("a different master key must be an error")
	}
	s.SetKeyBox(nil)
	if err := s.CheckNodeKeys(ctx); err == nil {
		t.Fatal("sealed keys without a master key must be an error")
	}
}

// The rollback refuses to drop the column while keys live only there.
func TestRollback009RefusesToLoseKeys(t *testing.T) {
	s := newTestStore(t)
	box, _ := secretbox.New(testMasterKey)
	s.SetKeyBox(box)
	ctx := context.Background()
	n := keyNode(t, s, map[string]string{})
	s.SetNodePrivateKey(ctx, n.ID, "real-key")
	down, err := os.ReadFile("migrations_rollback/009_node_keys_and_audit_user.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.ExecContext(ctx, string(down))
	conn.ExecContext(ctx, "ROLLBACK")
	conn.Close()
	if err == nil || !strings.Contains(err.Error(), "keys-to-labels") {
		t.Fatalf("down migration = %v, want a refusal naming keys-to-labels", err)
	}
	if key, _ := s.NodePrivateKey(ctx, n.ID); key != "real-key" {
		t.Fatalf("key after refused rollback = %q", key)
	}
}

// An empty legacy label is dropped, not sealed as an empty key.
func TestMigrateNodeKeysSkipsEmptyLabel(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	n := keyNode(t, s, map[string]string{"wireguard_private_key": ""})
	if _, _, err := s.MigrateNodeKeys(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNode(ctx, n.ID)
	if got.HasConfig {
		t.Fatal("an empty legacy key must not count as a config")
	}
	if _, ok := got.Labels["wireguard_private_key"]; ok {
		t.Fatalf("the empty label must be removed: %v", got.Labels)
	}
}

// A node and its sealed key are written together.
func TestCreateNodeWithKey(t *testing.T) {
	s := newTestStore(t)
	box, _ := secretbox.New(testMasterKey)
	s.SetKeyBox(box)
	ctx := context.Background()
	nw := keyNode(t, s, map[string]string{}) // reuse its network
	n := &models.Node{NetworkID: nw.NetworkID, Name: "keys-node-2", VirtualIP: net.ParseIP("10.72.0.3"),
		PublicKey: strings.Repeat("L", 43) + "=", Labels: map[string]string{}, Status: models.NodeStatusPending}
	if err := s.CreateNodeWithKey(ctx, n, "created-key"); err != nil {
		t.Fatal(err)
	}
	if key, _ := s.NodePrivateKey(ctx, n.ID); key != "created-key" {
		t.Fatalf("key = %q", key)
	}
}

// A key sealed by the first P4c build (v1, not bound to its node) still
// opens and is sealed again as v2 at startup.
func TestMigrateNodeKeysResealsV1(t *testing.T) {
	s := newTestStore(t)
	box, _ := secretbox.New(testMasterKey)
	s.SetKeyBox(box)
	ctx := context.Background()
	n := keyNode(t, s, map[string]string{})
	// What the first P4c build stored: AES-GCM without additional data.
	legacy := "v1:" + legacyV1(t, "old-key")
	s.db.ExecContext(ctx, "UPDATE nodes SET private_key_enc = $2 WHERE id = $1", n.ID, legacy)
	if err := s.CheckNodeKeys(ctx); err != nil {
		t.Fatalf("a v1 key must pass the startup check: %v", err)
	}
	if _, resealed, err := s.MigrateNodeKeys(ctx); err != nil || resealed < 1 {
		t.Fatalf("reseal = %d, %v", resealed, err)
	}
	if raw := storedKey(t, s, n.ID); !strings.HasPrefix(raw, "v2:") {
		t.Fatalf("after reseal = %q", raw)
	}
	if key, _ := s.NodePrivateKey(ctx, n.ID); key != "old-key" {
		t.Fatalf("key = %q", key)
	}
}

// legacyV1 seals plaintext the way the first P4c build did.
func legacyV1(t *testing.T, plaintext string) string {
	t.Helper()
	key, _ := hex.DecodeString(testMasterKey)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	return base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plaintext), nil))
}
