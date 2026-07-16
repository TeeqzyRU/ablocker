package utils

import (
	"os"
	"path/filepath"
	"testing"

	"ablocker/config"
)

func TestIsBypassedIP(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 10
TorrentTag: "TORRENT"
BypassIPS:
  - "127.0.0.1"
  - "192.168.1.100"
`

	configFile := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	err = config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if !IsBypassedIP("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to be bypassed")
	}

	if !IsBypassedIP("192.168.1.100") {
		t.Error("Expected 192.168.1.100 to be bypassed")
	}

	if IsBypassedIP("192.168.1.200") {
		t.Error("Expected 192.168.1.200 to not be bypassed")
	}
}

func TestIsBypassedIPCIDR(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_cidr_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 10
TorrentTag: "TORRENT"
BypassIPS:
  - "203.0.113.10"
  - "10.8.0.0/16"
  - "2001:db8::/32"
`
	configFile := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	if err := config.LoadConfig(configFile); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	cases := map[string]bool{
		"203.0.113.10":  true,  // exact IP
		"203.0.113.11":  false, // neighbour, not listed
		"10.8.5.42":     true,  // inside /16
		"10.9.0.1":      false, // outside /16
		"2001:db8::bad": true,  // inside IPv6 subnet
		"2001:dbff::1":  false, // outside IPv6 subnet
	}
	for ip, want := range cases {
		if got := IsBypassedIP(ip); got != want {
			t.Errorf("IsBypassedIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestParseDestHost(t *testing.T) {
	cases := map[string]string{
		`2025/12/06 00:00:14 from 1.2.3.4:5 accepted tcp:sub.evil.com:443 [in >> out] email: 1`: "sub.evil.com",
		`2025/12/06 00:00:14 from 1.2.3.4:5 accepted udp:185.10.10.10:443 [in >> out] email: 1`: "185.10.10.10",
		`2025/12/06 00:00:14 from 1.2.3.4:5 accepted tcp:[2a00::1]:443 [in >> out] email: 1`:    "2a00::1",
		`malformed line without accepted`: "",
	}
	for line, want := range cases {
		if got := parseDestHost(line); got != want {
			t.Errorf("parseDestHost(%q) = %q; want %q", line, got, want)
		}
	}
}

func TestSendWebhookDisabled(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 10
TorrentTag: "TORRENT"
SendWebhook: false
`

	configFile := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	err = config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	SendWebhook("testuser", "192.168.1.100", "block")
}
