package rest

import "testing"

// B21: the hub keeps the network's own prefix, not a hardcoded /24.
func TestHubAddress(t *testing.T) {
	for cidr, want := range map[string]string{
		"10.20.0.0/24":   "10.20.0.1/24",
		"10.20.0.0/16":   "10.20.0.1/16",
		"10.20.5.0/23":   "10.20.4.1/23", // host bits in the input are masked
		"192.168.7.0/28": "192.168.7.1/28",
	} {
		got, err := hubAddress(cidr)
		if err != nil || got != want {
			t.Errorf("hubAddress(%s) = %q, %v; want %s", cidr, got, err, want)
		}
	}
	if _, err := hubAddress("not-a-cidr"); err == nil {
		t.Error("an invalid CIDR must be an error")
	}
}
