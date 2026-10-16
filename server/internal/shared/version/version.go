// Package version holds the NovusGate release number. The panel
// (web/package.json) and NovusGate Center (its package.json) carry the same
// one; web/tests/version.test.mjs checks that they agree.
package version

// Version is the release, without a leading "v".
const Version = "0.7.0"
