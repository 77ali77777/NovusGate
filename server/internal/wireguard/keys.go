package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeys makes a WireGuard key pair the way `wg genkey | wg pubkey`
// does (a clamped Curve25519 scalar and its public point), in Go: no wg
// binary runs, so no AppArmor profile of the host can stop it.
func GenerateKeys() (privateKey string, publicKey string, err error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	privateKey = base64.StdEncoding.EncodeToString(k[:])
	publicKey, err = PublicKey(privateKey)
	return privateKey, publicKey, err
}

// PublicKey derives the public key of a base64 WireGuard private key, like
// `wg pubkey`.
func PublicKey(privateKey string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil || len(raw) != curve25519.ScalarSize {
		return "", fmt.Errorf("invalid WireGuard private key")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}
