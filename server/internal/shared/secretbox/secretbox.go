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
	prefixV1    = "v1:"
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

// Seal returns the stored form of plaintext: "v1:<base64(nonce|ciphertext)>"
// with a box, "plain:<plaintext>" without one.
func Seal(b *Box, plaintext string) (string, error) {
	if b == nil {
		return prefixPlain + plaintext, nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefixV1 + base64.StdEncoding.EncodeToString(sealed), nil
}

// Open returns the plaintext of a stored value. A "v1:" value needs the box
// that sealed it; a "plain:" value opens with or without one.
func Open(b *Box, stored string) (string, error) {
	if rest, ok := strings.CutPrefix(stored, prefixPlain); ok {
		return rest, nil
	}
	rest, ok := strings.CutPrefix(stored, prefixV1)
	if !ok {
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
	plain, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", errors.New("secret cannot be decrypted with this master key")
	}
	return string(plain), nil
}

// IsPlain reports whether a stored value is unencrypted.
func IsPlain(stored string) bool {
	return strings.HasPrefix(stored, prefixPlain)
}
