package secretbox

import (
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
	s1, err := Seal(b, "wg-private-key")
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := Seal(b, "wg-private-key")
	if !strings.HasPrefix(s1, "v1:") || strings.Contains(s1, "wg-private-key") || s1 == s2 {
		t.Fatalf("sealed = %q / %q: want v1:, no plaintext, a fresh nonce each time", s1, s2)
	}
	if got, err := Open(b, s1); err != nil || got != "wg-private-key" {
		t.Fatalf("open = %q, %v", got, err)
	}
}

func TestSecretboxWrongKey(t *testing.T) {
	a, _ := New(keyA)
	b, _ := New(keyB)
	sealed, _ := Seal(a, "secret")
	if got, err := Open(b, sealed); err == nil {
		t.Fatalf("a wrong key must fail, got %q", got)
	}
	if _, err := Open(nil, sealed); err == nil {
		t.Fatal("a v1 value without a key must fail")
	}
}

func TestSecretboxWithoutKeyStoresPlain(t *testing.T) {
	sealed, err := Seal(nil, "secret")
	if err != nil || sealed != "plain:secret" {
		t.Fatalf("seal without key = %q, %v", sealed, err)
	}
	if got, err := Open(nil, sealed); err != nil || got != "secret" {
		t.Fatalf("open plain = %q, %v", got, err)
	}
	b, _ := New(keyA)
	if got, err := Open(b, sealed); err != nil || got != "secret" {
		t.Fatalf("a keyed box must still open plain values: %q, %v", got, err)
	}
}

func TestSecretboxRejectsBadKeys(t *testing.T) {
	for _, k := range []string{"", "abc", strings.Repeat("z", 64), keyA[:62]} {
		if _, err := New(k); err == nil {
			t.Errorf("New(%q) must fail", k)
		}
	}
	if _, err := Open(nil, "garbage"); err == nil {
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
