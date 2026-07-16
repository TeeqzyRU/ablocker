package config

import (
	"fmt"
	"net"
	"os"
	"regexp"

	"gopkg.in/yaml.v2"
)

const (
	DefaultNoEmailUsername = "__NO_USER_NAME__"
)

var (
	LogFile       string
	BlockDuration int
	TorrentTag    string
	BlockMode     string
	BypassIPSet   = make(map[string]struct{})
	BypassNets    []*net.IPNet
	IgnoreEmail   bool
	StorageDir    string

	SendWebhook     bool
	WebhookURL      string
	WebhookTemplate string
	WebhookHeaders  map[string]string

	UsernameRegex        *regexp.Regexp
	DefaultUsernameRegex = `^(.+)$`

	Hostname string

	EnablePerformanceMetrics bool

	// Malware / botnet blocking (Vo1d/BadBox etc.)
	MalwareBlockEnabled  bool
	MalwareDomainFeeds   []string
	MalwareIPFeeds       []string
	MalwareAction        string
	MalwareBlockDuration int
	BlocklistReload      string
)

type Config struct {
	LogFile         string            `yaml:"LogFile"`
	BlockDuration   int               `yaml:"BlockDuration"`
	TorrentTag      string            `yaml:"TorrentTag"`
	UsernameRegex   string            `yaml:"UsernameRegex"`
	BlockMode       string            `yaml:"BlockMode"`
	BypassIPS       []string          `yaml:"BypassIPS"`
	IgnoreEmail     bool              `yaml:"IgnoreEmail"`
	SendWebhook     bool              `yaml:"SendWebhook"`
	WebhookURL      string            `yaml:"WebhookURL"`
	WebhookTemplate string            `yaml:"WebhookTemplate"`
	StorageDir      string            `yaml:"StorageDir"`
	WebhookHeaders  map[string]string `yaml:"WebhookHeaders"`
	Hostname        string            `yaml:"Hostname"`

	// Malware / botnet blocking
	MalwareBlockEnabled  bool     `yaml:"MalwareBlockEnabled"`
	MalwareDomainFeeds   []string `yaml:"MalwareDomainFeeds"`
	MalwareIPFeeds       []string `yaml:"MalwareIPFeeds"`
	MalwareAction        string   `yaml:"MalwareAction"`
	MalwareBlockDuration int      `yaml:"MalwareBlockDuration"`
	BlocklistReload      string   `yaml:"BlocklistReload"`
}

func LoadConfig(configPath string) error {
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var cfg Config
	err = yaml.Unmarshal(configFile, &cfg)
	if err != nil {
		return err
	}

	LogFile = cfg.LogFile
	BlockDuration = cfg.BlockDuration
	TorrentTag = cfg.TorrentTag
	IgnoreEmail = cfg.IgnoreEmail
	SendWebhook = cfg.SendWebhook
	WebhookURL = cfg.WebhookURL
	WebhookHeaders = cfg.WebhookHeaders

	if cfg.UsernameRegex != "" {
		UsernameRegex, err = regexp.Compile(cfg.UsernameRegex)
	} else {
		UsernameRegex, err = regexp.Compile(DefaultUsernameRegex)
	}
	if err != nil {
		return fmt.Errorf("invalid UsernameRegex pattern: %v", err)
	}

	if cfg.Hostname != "" {
		Hostname = cfg.Hostname
	} else {
		Hostname, err = os.Hostname()
	}

	if cfg.BlockMode != "" {
		BlockMode = cfg.BlockMode
	} else {
		BlockMode = "iptables"
	}
	if cfg.BypassIPS != nil {
		fmt.Println("Bypass IPS list:")
		BypassIPSet = make(map[string]struct{})
		BypassNets = nil
		for _, entry := range cfg.BypassIPS {
			// CIDR (e.g. 10.0.0.0/8) -> subnet match; otherwise exact IP.
			if _, ipNet, err := net.ParseCIDR(entry); err == nil {
				BypassNets = append(BypassNets, ipNet)
			} else {
				BypassIPSet[entry] = struct{}{}
			}
			fmt.Printf("- %s\n", entry)
		}
	} else {
		BypassIPSet = make(map[string]struct{})
		BypassNets = nil
	}
	if WebhookHeaders == nil {
		WebhookHeaders = make(map[string]string)
	}
	if cfg.WebhookTemplate != "" {
		WebhookTemplate = cfg.WebhookTemplate
	} else {
		WebhookTemplate = `{"username":"%s","ip":"%s","server":"%s","action":"%s","duration":%d,"timestamp":"%s"}`
	}

	StorageDir = cfg.StorageDir
	if StorageDir == "" {
		StorageDir = "/opt/ablocker"
	}

	// Malware / botnet blocking
	MalwareBlockEnabled = cfg.MalwareBlockEnabled
	MalwareDomainFeeds = cfg.MalwareDomainFeeds
	MalwareIPFeeds = cfg.MalwareIPFeeds
	MalwareAction = cfg.MalwareAction
	if MalwareAction == "" {
		MalwareAction = "ban"
	}
	MalwareBlockDuration = cfg.MalwareBlockDuration
	if MalwareBlockDuration == 0 {
		MalwareBlockDuration = 1440
	}
	BlocklistReload = cfg.BlocklistReload
	if BlocklistReload == "" {
		BlocklistReload = "30m"
	}

	return err
}
