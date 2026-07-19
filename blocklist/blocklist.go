package blocklist

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Category labels an indicator so the caller can pick a different action per
// type (e.g. "ban the IP" for torrents vs "disable the user" for botnets).
type Category string

const (
	CategoryMalware Category = "malware"
	CategoryBotnet  Category = "botnet"
	CategorySpam    Category = "spam"
)

// Source is one feed. Provide URL (remote) and/or Path (local file). Type tells
// the loader whether the lines are domains or IPs.
type Source struct {
	URL      string
	Path     string
	Category Category
	Type     string // "domain" or "ip"
}

// Shared CDN / anycast ranges are dropped from IP feeds. Malware hides behind
// Cloudflare, so its front-end address ends up in C2 IP lists — but that same
// address serves thousands of unrelated sites, and banning a client for
// touching it is a guaranteed false positive. Such malware is still caught by
// the domain feeds, which name the actual host. Extend via SetExcludeNets.
var defaultExcludeCIDRs = []string{
	// Cloudflare, published at https://www.cloudflare.com/ips/
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	// Public DNS resolvers — never ban a client for resolving names.
	"1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32",
	"9.9.9.9/32", "149.112.112.112/32", "208.67.222.222/32", "208.67.220.220/32",
}

var (
	excludeMu   sync.RWMutex
	excludeNets = parseCIDRs(defaultExcludeCIDRs)
)

func parseCIDRs(list []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, c := range list {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		} else {
			log.Printf("blocklist: ignoring bad exclude CIDR %q: %v", c, err)
		}
	}
	return out
}

// SetExcludeNets appends extra CIDRs to the built-in shared-CDN exclusions.
// Call before New(); takes effect on the next reload.
func SetExcludeNets(extra []string) {
	nets := parseCIDRs(defaultExcludeCIDRs)
	nets = append(nets, parseCIDRs(extra)...)
	excludeMu.Lock()
	excludeNets = nets
	excludeMu.Unlock()
}

// isExcludedIP reports whether an IP belongs to a shared CDN / anycast range
// and must never be treated as a malware indicator.
func isExcludedIP(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return false
	}
	excludeMu.RLock()
	defer excludeMu.RUnlock()
	for _, n := range excludeNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// Matcher holds the loaded indicators and answers O(1) lookups, with a
// background reloader so feeds stay fresh without a restart.
type Matcher struct {
	mu      sync.RWMutex
	domains map[string]Category
	ips     map[string]Category

	sources  []Source
	interval time.Duration
	client   *http.Client
}

// New loads every source once (synchronously) and, if reload > 0, starts a
// background refresh. A failing feed is logged and skipped so one dead source
// never takes the whole matcher down.
func New(sources []Source, reload time.Duration) *Matcher {
	m := &Matcher{
		domains:  make(map[string]Category),
		ips:      make(map[string]Category),
		sources:  sources,
		interval: reload,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
	m.reload()
	if reload > 0 {
		go m.reloadLoop()
	}
	return m
}

func (m *Matcher) reloadLoop() {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for range t.C {
		m.reload()
	}
}

// reload rebuilds both maps from scratch and swaps them in atomically.
func (m *Matcher) reload() {
	domains := make(map[string]Category)
	ips := make(map[string]Category)

	for _, s := range m.sources {
		n := 0
		if s.Path != "" {
			n += loadReader(openFile(s.Path), s, domains, ips)
		}
		if s.URL != "" {
			n += loadReader(m.openURL(s.URL), s, domains, ips)
		}
		log.Printf("blocklist: +%d %s indicators [%s] from %s%s",
			n, s.Type, s.Category, s.URL, s.Path)
	}

	m.mu.Lock()
	m.domains = domains
	m.ips = ips
	m.mu.Unlock()

	log.Printf("blocklist: active set — %d domains, %d ips", len(domains), len(ips))
}

func openFile(path string) io.ReadCloser {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("blocklist: cannot open %s: %v", path, err)
		return nil
	}
	return f
}

func (m *Matcher) openURL(url string) io.ReadCloser {
	resp, err := m.client.Get(url)
	if err != nil {
		log.Printf("blocklist: fetch %s failed: %v", url, err)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("blocklist: fetch %s returned %d", url, resp.StatusCode)
		resp.Body.Close()
		return nil
	}
	return resp.Body
}

// loadReader parses a line-based list (one indicator per line; #, // comments
// and blank lines skipped; hosts-file "0.0.0.0 domain" format tolerated).
func loadReader(r io.ReadCloser, s Source, domains, ips map[string]Category) int {
	if r == nil {
		return 0
	}
	defer r.Close()

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	n := 0
	skipped := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if s.Type == "ip" {
			if ip := parseIPToken(strings.ToLower(line)); ip != "" {
				if isExcludedIP(ip) {
					skipped++
					continue
				}
				ips[ip] = s.Category
				n++
			}
			continue
		}
		// "0.0.0.0 evil.com" / "127.0.0.1 evil.com" → take the last field.
		if strings.IndexAny(line, " \t") >= 0 {
			f := strings.Fields(line)
			line = f[len(f)-1]
		}
		line = strings.ToLower(line)

		line = strings.TrimPrefix(line, "*.")
		line = strings.TrimSuffix(line, ".")
		if line != "" {
			domains[line] = s.Category
			n++
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("blocklist: scan error: %v", err)
	}
	if skipped > 0 {
		log.Printf("blocklist: skipped %d shared-CDN/anycast ip(s) from %s%s (false-positive guard)",
			skipped, s.URL, s.Path)
	}
	return n
}

// parseIPToken extracts a bare IP from a feed token. Accepts "1.2.3.4",
// "1.2.3.4:443" / "[2001:db8::1]:443" (IP:port lines, e.g. SSLBL-style) and
// CSV rows — including quoted ones like ThreatFox exports:
//
//	"2026-06-14 12:25:44", "1832107", "195.222.53.130:6431", "ip:port", ...
//
// The first field that parses as an IP wins. Returns "" if no IP is found.
func parseIPToken(line string) string {
	if ip := bareIP(line); ip != "" {
		return ip
	}
	if strings.ContainsRune(line, ',') {
		for _, f := range strings.Split(line, ",") {
			if ip := bareIP(f); ip != "" {
				return ip
			}
		}
	}
	return ""
}

// bareIP strips whitespace/quotes and returns the token as an IP, accepting
// bare-IP and IP:port forms.
func bareIP(tok string) string {
	tok = strings.Trim(strings.TrimSpace(tok), `"'`)
	if net.ParseIP(tok) != nil {
		return tok
	}
	if host, _, err := net.SplitHostPort(tok); err == nil && net.ParseIP(host) != nil {
		return host
	}
	return ""
}

// Match checks a destination pulled from an access-log line. dest may be a bare
// IP or a domain. For domains it walks parent suffixes, so sub.evil.com matches
// a listed evil.com (but never a bare TLD). Returns the category on a hit.
func (m *Matcher) Match(dest string) (Category, bool) {
	dest = strings.ToLower(strings.TrimSpace(dest))
	if dest == "" {
		return "", false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if net.ParseIP(dest) != nil {
		c, ok := m.ips[dest]
		return c, ok
	}

	host := dest
	for {
		if c, ok := m.domains[host]; ok {
			return c, true
		}
		i := strings.IndexByte(host, '.')
		if i < 0 {
			break
		}
		rest := host[i+1:]
		if strings.IndexByte(rest, '.') < 0 { // <2 labels left → stop
			break
		}
		host = rest
	}
	return "", false
}

// Size reports current counts (handy for logs or a /health line).
func (m *Matcher) Size() (domains, ips int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.domains), len(m.ips)
}
