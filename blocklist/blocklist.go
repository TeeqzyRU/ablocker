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
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// "0.0.0.0 evil.com" / "127.0.0.1 evil.com" → take the last field.
		if strings.IndexAny(line, " \t") >= 0 {
			f := strings.Fields(line)
			line = f[len(f)-1]
		}
		line = strings.ToLower(line)

		if s.Type == "ip" {
			if net.ParseIP(line) != nil {
				ips[line] = s.Category
				n++
			}
			continue
		}
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
	return n
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
