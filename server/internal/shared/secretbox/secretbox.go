// Package secretbox seals secrets for storage with AES-256-GCM under a
// master key from the environment. Without a key, values are stored with a
// "plain:" prefix so existing installs keep working until a key is set.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// EnvVar holds the master key: 64 hex characters (32 bytes).
const EnvVar = "NOVUSGATE_MASTER_KEY"

const (
	prefixV1    = "v1:" // first P4c build: no additional data
	prefixV2    = "v2:" // bound to the owning row (additional data)
	prefixPlain = "plain:"
)

// Box seals and opens values with one master key.
type Box struct {
	aead cipher.AEAD
}

// New builds a Box from a 64-character hex key.
func New(hexKey string) (*Box, error) {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(key) != 32 {
		return nil, errors.New("master key must be 64 hex characters (32 bytes)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// FromEnv builds a Box from EnvVar; it returns nil, nil when the variable
// is unset or empty.
func FromEnv() (*Box, error) {
	v := os.Getenv(EnvVar)
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	b, err := New(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvVar, err)
	}
	return b, nil
}

// Seal returns the stored form of plaintext: "v2:<base64(nonce|ciphertext)>"
// with a box, "plain:<plaintext>" without one. context (the owning row's ID)
// is authenticated but not stored, so a value only opens for that row.
func Seal(b *Box, plaintext, context string) (string, error) {
	if b == nil {
		return prefixPlain + plaintext, nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := b.aead.Seal(nonce, nonce, []byte(plaintext), []byte(context))
	return prefixV2 + base64.StdEncoding.EncodeToString(sealed), nil
}

// Open returns the plaintext of a stored value. A "v2:" value needs the box
// and the context it was sealed with; a "v1:" value (written before the
// context binding) only the box; a "plain:" value opens with or without one.
func Open(b *Box, stored, context string) (string, error) {
	if rest, ok := strings.CutPrefix(stored, prefixPlain); ok {
		return rest, nil
	}
	var rest string
	var aad []byte
	if r, ok := strings.CutPrefix(stored, prefixV2); ok {
		rest, aad = r, []byte(context)
	} else if r, ok := strings.CutPrefix(stored, prefixV1); ok {
		rest = r
	} else {
		return "", errors.New("unknown secret format")
	}
	if b == nil {
		return "", fmt.Errorf("secret is encrypted but %s is not set", EnvVar)
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return "", fmt.Errorf("secret is not valid base64: %w", err)
	}
	n := b.aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("secret is too short")
	}
	plain, err := b.aead.Open(nil, raw[:n], raw[n:], aad)
	if err != nil {
		return "", errors.New("secret cannot be decrypted with this master key (or it belongs to another row)")
	}
	return string(plain), nil
}

// IsLegacy reports whether a stored value should be sealed again in the
// current format: plain text, or v1 (not bound to its row).
func IsLegacy(stored string) bool {
	return strings.HasPrefix(stored, prefixPlain) || strings.HasPrefix(stored, prefixV1)
}
