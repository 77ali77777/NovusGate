package secretbox

import (
	"encoding/base64"
	"strings"
	"testing"
)

const keyA = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const keyB = "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestSecretboxRoundTrip(t *testing.T) {
	b, err := New(keyA)
	if err != nil {
		t.Fatal(err)
	}
	s1, err := Seal(b, "wg-private-key", "n")
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := Seal(b, "wg-private-key", "n")
	if !strings.HasPrefix(s1, "v2:") || strings.Contains(s1, "wg-private-key") || s1 == s2 {
		t.Fatalf("sealed = %q / %q: want v2:, no plaintext, a fresh nonce each time", s1, s2)
	}
	if got, err := Open(b, s1, "n"); err != nil || got != "wg-private-key" {
		t.Fatalf("open = %q, %v", got, err)
	}
}

func TestSecretboxWrongKey(t *testing.T) {
	a, _ := New(keyA)
	b, _ := New(keyB)
	sealed, _ := Seal(a, "secret", "n")
	if got, err := Open(b, sealed, "n"); err == nil {
		t.Fatalf("a wrong key must fail, got %q", got)
	}
	if _, err := Open(nil, sealed, "n"); err == nil {
		t.Fatal("a v1 value without a key must fail")
	}
}

func TestSecretboxWithoutKeyStoresPlain(t *testing.T) {
	sealed, err := Seal(nil, "secret", "n")
	if err != nil || sealed != "plain:secret" {
		t.Fatalf("seal without key = %q, %v", sealed, err)
	}
	if got, err := Open(nil, sealed, "n"); err != nil || got != "secret" {
		t.Fatalf("open plain = %q, %v", got, err)
	}
	b, _ := New(keyA)
	if got, err := Open(b, sealed, "n"); err != nil || got != "secret" {
		t.Fatalf("a keyed box must still open plain values: %q, %v", got, err)
	}
}

func TestSecretboxRejectsBadKeys(t *testing.T) {
	for _, k := range []string{"", "abc", strings.Repeat("z", 64), keyA[:62]} {
		if _, err := New(k); err == nil {
			t.Errorf("New(%q) must fail", k)
		}
	}
	if _, err := Open(nil, "garbage", "n"); err == nil {
		t.Error("an unknown format must fail")
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv(EnvVar, "")
	if b, err := FromEnv(); b != nil || err != nil {
		t.Fatalf("unset = %v, %v", b, err)
	}
	t.Setenv(EnvVar, "nope")
	if _, err := FromEnv(); err == nil {
		t.Fatal("an invalid key must be an error")
	}
	t.Setenv(EnvVar, keyA)
	if b, err := FromEnv(); b == nil || err != nil {
		t.Fatalf("valid = %v, %v", b, err)
	}
}

// A sealed value is bound to its context (the node ID): it does not open
// for another one, so values cannot be swapped between rows.
func TestSecretboxBindsContext(t *testing.T) {
	b, _ := New(keyA)
	sealed, _ := Seal(b, "secret", "node-a")
	if _, err := Open(b, sealed, "node-b"); err == nil {
		t.Fatal("a value sealed for node-a must not open for node-b")
	}
	if got, err := Open(b, sealed, "node-a"); err != nil || got != "secret" {
		t.Fatalf("open = %q, %v", got, err)
	}
}

// Values sealed before the node-ID binding (v1, no additional data) still
// open, so existing databases keep working; new values are v2.
func TestSecretboxOpensLegacyV1(t *testing.T) {
	b, _ := New(keyA)
	sealed, _ := Seal(b, "secret", "node-a")
	if !strings.HasPrefix(sealed, "v2:") {
		t.Fatalf("new values must be v2, got %q", sealed[:3])
	}
	legacy := legacySealV1(t, b, "old-secret")
	if got, err := Open(b, legacy, "any-node"); err != nil || got != "old-secret" {
		t.Fatalf("a v1 value must still open: %q, %v", got, err)
	}
	if !IsLegacy(legacy) || IsLegacy(sealed) {
		t.Fatal("IsLegacy must tell v1 from v2")
	}
}

// legacySealV1 seals like the first P4c build: no additional data.
func legacySealV1(t *testing.T, b *Box, plaintext string) string {
	t.Helper()
	nonce := make([]byte, b.aead.NonceSize())
	return "v1:" + base64.StdEncoding.EncodeToString(b.aead.Seal(nonce, nonce, []byte(plaintext), nil))
}
