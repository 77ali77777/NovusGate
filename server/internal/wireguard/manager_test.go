package wireguard

import (
	"strings"
	"testing"
)

// B22: base64 keys end in '='; splitting on every '=' dropped it.
func TestParsePrivateKeyKeepsPadding(t *testing.T) {
	key := strings.Repeat("a", 43) + "="
	for _, conf := range []string{
		"[Interface]\nPrivateKey = " + key + "\nListenPort = 51820\n",
		"[Interface]\nPrivateKey=" + key + "\n",
		"[Interface]\r\nPrivateKey =  " + key + "  \r\n",
	} {
		if got := parsePrivateKey(conf); got != key {
			t.Errorf("parsePrivateKey(%q) = %q, want %q", conf, got, key)
		}
	}
	if got := parsePrivateKey("[Interface]\nListenPort = 1\n"); got != "" {
		t.Errorf("no key must give empty, got %q", got)
	}
}
