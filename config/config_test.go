package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 15
TorrentTag: "TEST_TORRENT"
UsernameRegex: "user: (\\S+)"
BlockMode: "iptables"
IgnoreEmail: true
BypassIPS:
  - "127.0.0.1"
  - "192.168.1.1"
SendWebhook: true
WebhookURL: "https://test.com/webhook"
WebhookTemplate: '{"test":"%s"}'
StorageDir: "/tmp/test"
WebhookHeaders:
  Authorization: "Bearer test-token"
`

	tmpFile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config content: %v", err)
	}
	tmpFile.Close()

	err = LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if LogFile != "/var/log/test.log" {
		t.Errorf("Expected LogFile '/var/log/test.log', got '%s'", LogFile)
	}

	if BlockDuration != 15 {
		t.Errorf("Expected BlockDuration 15, got %d", BlockDuration)
	}

	if TorrentTag != "TEST_TORRENT" {
		t.Errorf("Expected TorrentTag 'TEST_TORRENT', got '%s'", TorrentTag)
	}

	if BlockMode != "iptables" {
		t.Errorf("Expected BlockMode 'iptables', got '%s'", BlockMode)
	}

	if !SendWebhook {
		t.Error("Expected SendWebhook to be true")
	}

	if !IgnoreEmail {
		t.Error("Expected IgnoreEmail to be true")
	}

	if WebhookURL != "https://test.com/webhook" {
		t.Errorf("Expected WebhookURL 'https://test.com/webhook', got '%s'", WebhookURL)
	}

	if StorageDir != "/tmp/test" {
		t.Errorf("Expected StorageDir '/tmp/test', got '%s'", StorageDir)
	}

	if _, exists := BypassIPSet["127.0.0.1"]; !exists {
		t.Error("Expected 127.0.0.1 to be in BypassIPSet")
	}

	if _, exists := BypassIPSet["192.168.1.1"]; !exists {
		t.Error("Expected 192.168.1.1 to be in BypassIPSet")
	}

	if WebhookHeaders["Authorization"] != "Bearer test-token" {
		t.Errorf("Expected Authorization header 'Bearer test-token', got '%s'", WebhookHeaders["Authorization"])
	}
}

func TestLoadConfigWithDefaults(t *testing.T) {
	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 10
TorrentTag: "TORRENT"
`

	tmpFile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config content: %v", err)
	}
	tmpFile.Close()

	err = LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if BlockMode != "iptables" {
		t.Errorf("Expected default BlockMode 'iptables', got '%s'", BlockMode)
	}

	if SendWebhook {
		t.Error("Expected default SendWebhook to be false")
	}

	if StorageDir != "/opt/ablocker" {
		t.Errorf("Expected default StorageDir '/opt/ablocker', got '%s'", StorageDir)
	}

	if UsernameRegex == nil {
		t.Error("Expected UsernameRegex to be compiled")
	}

	if MalwareAction != "ban" {
		t.Errorf("Expected default MalwareAction 'ban', got '%s'", MalwareAction)
	}

	if MalwareBlockDuration != 1440 {
		t.Errorf("Expected default MalwareBlockDuration 1440, got %d", MalwareBlockDuration)
	}
}

func TestLoadConfigInvalidFile(t *testing.T) {
	err := LoadConfig("/nonexistent/file.yaml")
	if err == nil {
		t.Error("Expected error when loading nonexistent file")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: "invalid"
`

	tmpFile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config content: %v", err)
	}
	tmpFile.Close()

	err = LoadConfig(tmpFile.Name())
	if err == nil {
		t.Error("Expected error when loading invalid YAML")
	}
}

func loadFromString(t *testing.T, body string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "cfg_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := LoadConfig(f.Name()); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
}

func TestFanoutDefaultsForConfigWithoutKeys(t *testing.T) {
	// A config written before the feature existed: an upgrade must turn the
	// detector on in log-only mode, never start banning by itself.
	loadFromString(t, "LogFile: \"/var/log/x.log\"\nBlockDuration: 43200\nTorrentTag: \"TORRENT\"\n")
	if !FanoutEnabled || FanoutAction != "log" || FanoutThreshold != 150 || FanoutWindow != "10m" {
		t.Fatalf("defaults = enabled:%v action:%q threshold:%d window:%q; want true, log, 150, 10m",
			FanoutEnabled, FanoutAction, FanoutThreshold, FanoutWindow)
	}
}

func TestFanoutExplicitSettings(t *testing.T) {
	loadFromString(t, "FanoutEnabled: true\nFanoutAction: \"ban\"\nFanoutThreshold: 200\nFanoutWindow: \"5m\"\nFanoutIgnorePorts: [27015, 3074]\n")
	if !FanoutEnabled || FanoutAction != "ban" || FanoutThreshold != 200 || FanoutWindow != "5m" || len(FanoutIgnorePorts) != 2 {
		t.Fatalf("got enabled:%v action:%q threshold:%d window:%q ports:%v",
			FanoutEnabled, FanoutAction, FanoutThreshold, FanoutWindow, FanoutIgnorePorts)
	}

	loadFromString(t, "FanoutEnabled: false\n")
	if FanoutEnabled {
		t.Fatal("FanoutEnabled: false must disable the detector")
	}

	loadFromString(t, "FanoutAction: \"kill\"\n")
	if FanoutAction != "log" {
		t.Fatalf("unknown action must fall back to log, got %q", FanoutAction)
	}
}

func TestShippedDefaultConfigFanoutIsLogOnly(t *testing.T) {
	// The config.yaml.default that the installer copies on fresh nodes must
	// parse and must never ship the detector in ban mode.
	if err := LoadConfig("../config.yaml.default"); err != nil {
		t.Fatalf("config.yaml.default: %v", err)
	}
	if !FanoutEnabled || FanoutAction != "log" || FanoutThreshold != 150 || FanoutWindow != "10m" {
		t.Fatalf("shipped defaults = enabled:%v action:%q threshold:%d window:%q; want true, log, 150, 10m",
			FanoutEnabled, FanoutAction, FanoutThreshold, FanoutWindow)
	}
}
