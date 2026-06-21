package utils

import (
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"ablocker/blocklist"
	"ablocker/config"
	"ablocker/firewall"
	"ablocker/storage"

	"github.com/nxadm/tail"
)

var ipStorage *storage.IPStorage
var firewallManager *firewall.Manager
var malwareMatcher *blocklist.Matcher

var (
	parseStats struct {
		totalLines   int64
		validLines   int64
		invalidLines int64
		totalTime    time.Duration
		mu           sync.RWMutex
	}
	metricsStartTime time.Time
)

var (
	torrentTagBytes []byte
	fromBytes       []byte
	emailBytes      []byte
	acceptedBytes   []byte
)

func init() {
	metricsStartTime = time.Now()
}

func initializeByteSearchPatterns() {
	torrentTagBytes = []byte(config.TorrentTag)
	fromBytes = []byte("from ")
	emailBytes = []byte("email: ")
	acceptedBytes = []byte("accepted ")

	log.Printf("Initialized byte search patterns: TorrentTag='%s' (%d bytes)",
		config.TorrentTag, len(torrentTagBytes))
}

func StartLogMonitor() {
	t, err := tail.TailFile(config.LogFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2},
		MustExist: false,
	})
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}

	for line := range t.Lines {
		lineBytes := stringToBytes(line.Text)

		hasTorrentTag := containsBytes(lineBytes, torrentTagBytes)

		if config.EnablePerformanceMetrics {
			parseStart := time.Now()
			parseDuration := time.Since(parseStart)

			updateParseStats(parseDuration, hasTorrentTag)
		}

		if hasTorrentTag {
			handleLogEntry(line.Text)
			continue
		}

		if malwareMatcher != nil {
			if dst := parseDestHost(line.Text); dst != "" {
				if cat, hit := malwareMatcher.Match(dst); hit {
					handleMalwareEntry(line.Text, dst, string(cat))
				}
			}
		}
	}
}

func parseLogEntryFast(line string) (ip, username string, valid bool) {
	lineBytes := stringToBytes(line)

	if !containsBytes(lineBytes, torrentTagBytes) {
		return "", "", false
	}

	fromIndex := indexBytes(lineBytes, fromBytes)
	if fromIndex == -1 {
		return "", "", false
	}

	ipStart := fromIndex + len(fromBytes)
	if ipStart >= len(line) {
		return "", "", false
	}

	if ipStart+4 < len(line) {
		if (line[ipStart] == 't' && line[ipStart+1] == 'c' && line[ipStart+2] == 'p' && line[ipStart+3] == ':') ||
			(line[ipStart] == 'u' && line[ipStart+1] == 'd' && line[ipStart+2] == 'p' && line[ipStart+3] == ':') {
			ipStart += 4
		}
	}

	if ipStart >= len(line) {
		return "", "", false
	}

	ipEnd := ipStart
	for ipEnd < len(line) && line[ipEnd] != ':' {
		ipEnd++
	}

	if ipEnd <= ipStart {
		return "", "", false
	}

	ip = line[ipStart:ipEnd]

	if !isValidIPFormat(ip) {
		return "", "", false
	}

	emailIndex := indexBytes(lineBytes, emailBytes)
	if emailIndex == -1 {
		if config.IgnoreEmail {
			return ip, config.DefaultNoEmailUsername, true
		}
		return "", "", false
	}

	userStart := emailIndex + len(emailBytes)
	if userStart >= len(line) {
		return "", "", false
	}

	userEnd := userStart
	for userEnd < len(line) && line[userEnd] != ' ' && line[userEnd] != '\t' && line[userEnd] != '\n' {
		userEnd++
	}

	if userEnd <= userStart {
		return "", "", false
	}

	username = line[userStart:userEnd]
	return ip, username, true
}

// parseDestHost extracts the destination host (domain or IP) from a log line:
//
//	... accepted tcp:sub.evil.com:443 [..]  -> "sub.evil.com"
//	... accepted udp:185.10.10.10:443 [..]  -> "185.10.10.10"
//	... accepted tcp:[2a00::1]:443 [..]     -> "2a00::1"
func parseDestHost(line string) string {
	idx := indexBytes(stringToBytes(line), acceptedBytes)
	if idx == -1 {
		return ""
	}
	p := idx + len(acceptedBytes)
	if p+4 <= len(line) &&
		((line[p] == 't' && line[p+1] == 'c' && line[p+2] == 'p' && line[p+3] == ':') ||
			(line[p] == 'u' && line[p+1] == 'd' && line[p+2] == 'p' && line[p+3] == ':')) {
		p += 4
	}
	if p >= len(line) {
		return ""
	}
	if line[p] == '[' { // IPv6 literal
		end := p + 1
		for end < len(line) && line[end] != ']' {
			end++
		}
		if end < len(line) {
			return line[p+1 : end]
		}
		return ""
	}
	end := p
	for end < len(line) && line[end] != ':' && line[end] != ' ' {
		end++
	}
	return line[p:end]
}

// parseIPAndUser pulls source IP and username from a line, regardless of tag.
func parseIPAndUser(line string) (ip, user string) {
	lb := stringToBytes(line)

	if fi := indexBytes(lb, fromBytes); fi != -1 {
		s := fi + len(fromBytes)
		if s+4 < len(line) &&
			((line[s] == 't' && line[s+1] == 'c' && line[s+2] == 'p' && line[s+3] == ':') ||
				(line[s] == 'u' && line[s+1] == 'd' && line[s+2] == 'p' && line[s+3] == ':')) {
			s += 4
		}
		e := s
		for e < len(line) && line[e] != ':' {
			e++
		}
		if e > s && isValidIPFormat(line[s:e]) {
			ip = line[s:e]
		}
	}

	if ei := indexBytes(lb, emailBytes); ei != -1 {
		s := ei + len(emailBytes)
		e := s
		for e < len(line) && line[e] != ' ' && line[e] != '\t' && line[e] != '\n' {
			e++
		}
		if e > s {
			user = line[s:e]
		}
	} else if config.IgnoreEmail {
		user = config.DefaultNoEmailUsername
	}

	return ip, user
}

func handleLogEntry(line string) {
	ip, usernameStr, valid := parseLogEntryFast(line)

	if !valid {
		log.Println("Invalid log entry format: IP or username missing")
		return
	}

	if IsBypassedIP(ip) {
		return
	}

	if ipStorage.IsBlocked(ip) {
		log.Printf("User %s with IP: %s is already blocked. Skipping...\n", usernameStr, ip)
		return
	}

	if err := ipStorage.AddBlockedIP(ip, usernameStr, time.Duration(config.BlockDuration)*time.Minute); err != nil {
		log.Printf("Error saving blocked IP to storage: %v", err)
	}

	go BlockIP(ip)
	log.Printf("User %s with IP: %s blocked for %d minutes (torrent)\n", usernameStr, ip, config.BlockDuration)

	if config.SendWebhook {
		go SendWebhook(usernameStr, ip, "block")
	}
}

// handleMalwareEntry blocks a user whose traffic hit a malware/botnet indicator.
// Unlike a torrent (a slap on the wrist), an infected device reconnects, so the
// default action is a long ban; with action=disable it also fires a webhook so
// the panel can disable the user across all nodes.
func handleMalwareEntry(line, dst, category string) {
	ip, user := parseIPAndUser(line)
	if ip == "" {
		return
	}
	if IsBypassedIP(ip) {
		return
	}
	if ipStorage.IsBlocked(ip) {
		return
	}

	log.Printf("MALWARE hit: user=%s ip=%s dst=%s category=%s action=%s",
		user, ip, dst, category, config.MalwareAction)

	dur := time.Duration(config.MalwareBlockDuration) * time.Minute

	if config.MalwareAction == "disable" && config.SendWebhook {
		go SendWebhook(user, ip, "malware_disable")
	}

	if err := ipStorage.AddBlockedIP(ip, user, dur); err != nil {
		log.Printf("Error saving blocked IP to storage: %v", err)
	}
	go BlockIP(ip)

	if config.MalwareAction != "disable" && config.SendWebhook {
		go SendWebhook(user, ip, "malware_block")
	}
}

func BlockIP(ip string) {
	if firewallManager == nil {
		log.Printf("Firewall manager not initialized")
		return
	}

	err := firewallManager.BlockIP(ip)
	if err != nil {
		log.Printf("Error blocking IP %s: %v", ip, err)
		return
	}

	if conntrackManager != nil && conntrackManager.IsAvailable() {
		if err := conntrackManager.DropConnections(ip); err != nil {
			log.Printf("Warning: failed to drop connections for IP %s: %v", ip, err)
		}
	}
}

func SetFirewallManager(manager *firewall.Manager) {
	firewallManager = manager
	initializeByteSearchPatterns()

	if config.EnablePerformanceMetrics {
		log.Printf("Performance metrics enabled - starting metrics collection")
		go reportPerformanceMetrics()
	}
}

func SetIPStorage(storage *storage.IPStorage) {
	ipStorage = storage
}

// SetMalwareMatcher wires the blocklist matcher used for malware/botnet detection.
func SetMalwareMatcher(m *blocklist.Matcher) {
	malwareMatcher = m
}

func UpdateBlockedIPs() {
	if firewallManager == nil {
		log.Printf("Firewall manager not initialized")
		return
	}

	currentBlockedIPs, err := firewallManager.GetBlockedIPs()
	if err != nil {
		log.Printf("Error checking firewall status: %v", err)
		return
	}

	blockedInStorage := ipStorage.GetBlockedIPs()

	for ip, info := range blockedInStorage {
		if time.Now().Before(info.BlockedUntil) && !currentBlockedIPs[ip] {
			log.Printf("Restoring block for IP: %s (user: %s) using %s", ip, info.Username, firewallManager.GetFirewallName())
			go BlockIP(ip)
		}
	}
}

func ScheduleBlockedIPsUpdate() {
	UpdateBlockedIPs()
	go func() {
		for range time.Tick(time.Duration(config.BlockDuration) * time.Minute) {
			UpdateBlockedIPs()
		}
	}()
}

func UnblockIPAfterDelay(ip string, delay time.Duration, username string) {
	time.Sleep(delay)

	if ipStorage.IsBlocked(ip) {
		log.Printf("Skipping unblock for IP %s as it has an active block", ip)
		return
	}

	if firewallManager == nil {
		log.Printf("Firewall manager not initialized")
		return
	}

	blockedIPs := ipStorage.GetBlockedIPs()
	if _, exists := blockedIPs[ip]; !exists {
		log.Printf("IP %s not found in storage, skipping unblock", ip)
		return
	}

	err := firewallManager.UnblockIP(ip)
	if err != nil {
		if strings.Contains(err.Error(), "no rule found") || strings.Contains(err.Error(), "exit status 1") {
			log.Printf("IP %s already unblocked or rule not found, continuing...", ip)
		} else {
			log.Printf("Error unblocking IP %s: %v", ip, err)
			return
		}
	}

	if err := ipStorage.RemoveBlockedIP(ip); err != nil {
		log.Printf("Error removing IP from storage: %v", err)
	}

	log.Printf("User %s with IP: %s has been unblocked\n", username, ip)

	if config.SendWebhook {
		go SendWebhook(username, ip, "unblock")
	}
}

func IsBypassedIP(ip string) bool {
	_, exists := config.BypassIPSet[ip]
	return exists
}

func isValidIPFormat(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}

		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}

	return true
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}

	first := needle[0]
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i] == first {
			match := true
			for j := 1; j < len(needle); j++ {
				if haystack[i+j] != needle[j] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(haystack) {
		return -1
	}

	first := needle[0]
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i] == first {
			match := true
			for j := 1; j < len(needle); j++ {
				if haystack[i+j] != needle[j] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
}

func stringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&struct {
		string
		int
	}{s, len(s)}))
}

func SendWebhook(username string, ip string, action string) {
	if !config.SendWebhook || config.WebhookURL == "" {
		return
	}

	cleanUsername := processUsernameForWebhook(username)

	payload := fmt.Sprintf(
		config.WebhookTemplate,
		cleanUsername,
		ip,
		config.Hostname,
		action,
		config.BlockDuration,
		time.Now().Format(time.RFC3339),
	)

	req, err := http.NewRequest("POST", config.WebhookURL, strings.NewReader(payload))
	if err != nil {
		log.Printf("Error creating webhook request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range config.WebhookHeaders {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending webhook: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Webhook returned unexpected status code: %d", resp.StatusCode)
	}
}

func processUsernameForWebhook(rawUsername string) string {
	if config.UsernameRegex == nil {
		return rawUsername
	}

	matches := config.UsernameRegex.FindStringSubmatch(rawUsername)
	if len(matches) > 1 {
		return matches[1]
	}

	return rawUsername
}

func updateParseStats(duration time.Duration, valid bool) {
	if !config.EnablePerformanceMetrics {
		return
	}

	parseStats.mu.Lock()
	defer parseStats.mu.Unlock()

	parseStats.totalLines++
	parseStats.totalTime += duration

	if valid {
		parseStats.validLines++
	} else {
		parseStats.invalidLines++
	}
}

func reportPerformanceMetrics() {
	if !config.EnablePerformanceMetrics {
		return
	}

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	for range ticker.C {
		parseStats.mu.RLock()

		if parseStats.totalLines > 0 {
			runtime.ReadMemStats(&m2)

			avgTime := parseStats.totalTime / time.Duration(parseStats.totalLines)
			uptime := time.Since(metricsStartTime)
			linesPerSec := float64(parseStats.totalLines) / uptime.Seconds()
			torrentRate := float64(parseStats.validLines) / float64(parseStats.totalLines) * 100

			allocDiff := m2.TotalAlloc - m1.TotalAlloc
			gcDiff := m2.NumGC - m1.NumGC
			heapInUse := m2.HeapInuse / 1024 / 1024

			log.Printf("PERFORMANCE METRICS: Total Lines: %d, Torrent Lines: %.1f%% (%d/%d), Avg parse time: %v, Lines/sec: %.0f, Allocs: %d bytes, GC: %d, Heap: %d MB, Uptime: %v",
				parseStats.totalLines,
				torrentRate,
				parseStats.validLines,
				parseStats.totalLines,
				avgTime,
				linesPerSec,
				allocDiff,
				gcDiff,
				heapInUse,
				uptime.Truncate(time.Second))

			m1 = m2
		}

		parseStats.mu.RUnlock()
	}
}
