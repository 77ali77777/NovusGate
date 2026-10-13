package main

import (
	"strings"
	"testing"
)

func TestMaskDatabaseURLHidesPassword(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://novus:s3cr3t@postgres:5432/novusgate?sslmode=disable": "postgres://novus:xxxxx@postgres:5432/novusgate?sslmode=disable",
		"host=postgres user=novus password=s3cr3t dbname=novusgate":        "host=postgres user=novus password=xxxxx dbname=novusgate",
		"postgres://postgres:5432/novusgate":                              "postgres://postgres:5432/novusgate",
	} {
		got := maskDatabaseURL(in)
		if got != want || strings.Contains(got, "s3cr3t") {
			t.Errorf("maskDatabaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// Passwords that url.Parse cannot handle or that sit outside the userinfo
// must still never reach the logs.
func TestMaskDatabaseURLHidesUnusualPasswords(t *testing.T) {
	for _, in := range []string{
		"postgres://novus:p#ss/w@rd@postgres:5432/novusgate?sslmode=disable", // unencoded, as compose builds it
		"postgres://novus@postgres/novusgate?password=s3cr3t&sslmode=disable",
		"host=postgres user=novus password='s3cr3t with spaces' dbname=novusgate",
		"host=postgres user=novus password = s3cr3t dbname=novusgate",
	} {
		got := maskDatabaseURL(in)
		for _, secret := range []string{"s3cr3t", "p#ss", "w@rd", "spaces"} {
			if strings.Contains(got, secret) {
				t.Errorf("maskDatabaseURL(%q) = %q leaks %q", in, got, secret)
			}
		}
		if !strings.Contains(got, "xxxxx") {
			t.Errorf("maskDatabaseURL(%q) = %q, want the password replaced by xxxxx", in, got)
		}
	}
}
