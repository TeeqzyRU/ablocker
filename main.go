package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"ablocker/blocklist"
	"ablocker/config"
	"ablocker/firewall"
	"ablocker/storage"
	"ablocker/utils"
)

var Version string

func main() {
	initConfig()

	log.Printf("ablocker (Xray abuse blocker): %s", Version)
	log.Printf("Service started on %s", config.Hostname)

	utils.InitConntrackManager()

	utils.StartLogMonitor()
}

func initConfig() {
	var configPath string
	var showVersion bool
	var enablePerf bool

	flag.StringVar(&configPath, "c", "", "Path to the configuration file")
	flag.BoolVar(&showVersion, "v", false, "Display version")
	flag.BoolVar(&enablePerf, "perf", false, "Enable performance metrics collection")
	flag.Parse()

	if showVersion {
		fmt.Printf("ablocker (Xray abuse blocker): %s\n", Version)
		os.Exit(0)
	}

	if configPath == "" {
		ex, err := os.Executable()
		if err != nil {
			log.Fatalf("Error getting executable path: %v", err)
		}
		configPath = filepath.Join(filepath.Dir(ex), "config.yaml")
	}

	if err := config.LoadConfig(configPath); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	config.EnablePerformanceMetrics = enablePerf

	firewallManager, err := firewall.NewManager(config.BlockMode)
	if err != nil {
		log.Fatalf("Failed to initialize firewall manager: %v", err)
	}
	log.Printf("Using firewall: %s", firewallManager.GetFirewallName())
	utils.SetFirewallManager(firewallManager)

	store, err := storage.NewIPStorage(config.StorageDir, utils.UnblockIPAfterDelay)
	if err != nil {
		log.Fatalf("Failed to initialize IP storage: %v", err)
	}
	utils.SetIPStorage(store)

	if config.MalwareBlockEnabled {
		var sources []blocklist.Source
		for _, u := range config.MalwareDomainFeeds {
			sources = append(sources, blocklist.Source{URL: u, Category: blocklist.CategoryMalware, Type: "domain"})
		}
		for _, u := range config.MalwareIPFeeds {
			sources = append(sources, blocklist.Source{URL: u, Category: blocklist.CategoryBotnet, Type: "ip"})
		}
		reload, perr := time.ParseDuration(config.BlocklistReload)
		if perr != nil || reload <= 0 {
			reload = 30 * time.Minute
		}
		blocklist.SetExcludeNets(config.MalwareIPExclude)
		matcher := blocklist.New(sources, reload)
		d, i := matcher.Size()
		log.Printf("Malware blocking enabled: %d domains, %d ips loaded (action=%s, duration=%dm)",
			d, i, config.MalwareAction, config.MalwareBlockDuration)
		utils.SetMalwareMatcher(matcher)
	}

	utils.ScheduleBlockedIPsUpdate()
}
