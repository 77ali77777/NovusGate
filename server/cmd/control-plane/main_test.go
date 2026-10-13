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
