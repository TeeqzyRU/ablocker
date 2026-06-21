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
