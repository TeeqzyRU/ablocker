package blocklist

import (
	"io"
	"strings"
	"testing"
)

func TestParseIPToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.2.3.4", "1.2.3.4"},                         // bare IPv4
		{"1.2.3.4:443", "1.2.3.4"},                     // SSLBL-style IP:port
		{"[2001:db8::1]:443", "2001:db8::1"},           // IPv6 with port
		{"2001:db8::1", "2001:db8::1"},                 // bare IPv6
		{"2025-01-03 10:00:00,1.2.3.4,443", "1.2.3.4"}, // CSV: Firstseen,DstIP,DstPort
		{"10:00:00,5.6.7.8,447", "5.6.7.8"},            // CSV tail after hosts-field split
		{`"1.2.3.4:443"`, "1.2.3.4"},                   // quoted IP:port token
		{`"2026-06-14 12:25:44", "1832107", "195.222.53.130:6431", "ip:port", "botnet_cc"`, "195.222.53.130"}, // ThreatFox CSV row
		{"evil.com", ""},     // domain is not an IP
		{"evil.com:443", ""}, // domain:port is not an IP
		{"not,an,ip", ""},    // CSV without IPs
		{"", ""},             // empty
	}
	for _, c := range cases {
		if got := parseIPToken(c.in); got != c.want {
			t.Errorf("parseIPToken(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func loadFromString(t *testing.T, s Source, body string) (map[string]Category, map[string]Category) {
	t.Helper()
	domains := make(map[string]Category)
	ips := make(map[string]Category)
	loadReader(io.NopCloser(strings.NewReader(body)), s, domains, ips)
	return domains, ips
}

func TestLoadIPFeedFormats(t *testing.T) {
	feed := `# comment
1.2.3.4
5.6.7.8:447
2025-01-03 10:00:00,45.9.9.9,443
garbage-line
`
	_, ips := loadFromString(t, Source{Type: "ip", Category: CategoryBotnet}, feed)
	for _, want := range []string{"1.2.3.4", "5.6.7.8", "45.9.9.9"} {
		if _, ok := ips[want]; !ok {
			t.Errorf("ip %s not loaded; got %v", want, ips)
		}
	}
	if len(ips) != 3 {
		t.Errorf("want 3 ips, got %d: %v", len(ips), ips)
	}
}

func TestLoadDomainHostsFile(t *testing.T) {
	feed := "0.0.0.0 evil.com\n127.0.0.1 bad.org\n# note\nplain.net\n"
	domains, _ := loadFromString(t, Source{Type: "domain", Category: CategoryMalware}, feed)
	for _, want := range []string{"evil.com", "bad.org", "plain.net"} {
		if _, ok := domains[want]; !ok {
			t.Errorf("domain %s not loaded; got %v", want, domains)
		}
	}
}

func TestExcludeSharedCDNFromIPFeeds(t *testing.T) {
	// Addresses that actually caused false-positive bans in production: they
	// are Cloudflare front-ends listed in ThreatFox, but they serve thousands
	// of legitimate sites.
	feed := `188.114.96.0
188.114.96.3
188.114.97.0
188.114.97.3
104.21.7.84
172.67.71.251
1.1.1.1
8.8.8.8
45.137.22.99
`
	_, ips := loadFromString(t, Source{Type: "ip", Category: CategoryBotnet}, feed)

	for _, cdn := range []string{
		"188.114.96.0", "188.114.96.3", "188.114.97.0", "188.114.97.3",
		"104.21.7.84", "172.67.71.251", "1.1.1.1", "8.8.8.8",
	} {
		if _, ok := ips[cdn]; ok {
			t.Errorf("shared-CDN/resolver ip %s must be excluded from the feed", cdn)
		}
	}
	// A regular bulletproof-hosting C2 address must still be loaded.
	if _, ok := ips["45.137.22.99"]; !ok {
		t.Error("regular C2 ip 45.137.22.99 should still be loaded")
	}
	if len(ips) != 1 {
		t.Errorf("want exactly 1 ip after filtering, got %d: %v", len(ips), ips)
	}
}

func TestSetExcludeNetsAddsCustomRanges(t *testing.T) {
	defer SetExcludeNets(nil) // restore built-in defaults for other tests

	SetExcludeNets([]string{"203.0.113.0/24"})
	feed := "203.0.113.7\n198.51.100.9\n"
	_, ips := loadFromString(t, Source{Type: "ip", Category: CategoryBotnet}, feed)

	if _, ok := ips["203.0.113.7"]; ok {
		t.Error("ip from a custom excluded range must not be loaded")
	}
	if _, ok := ips["198.51.100.9"]; !ok {
		t.Error("ip outside excluded ranges should be loaded")
	}
}

func TestMatchSuffixWalk(t *testing.T) {
	m := &Matcher{
		domains: map[string]Category{"evil.com": CategoryMalware},
		ips:     map[string]Category{"9.9.9.9": CategoryBotnet},
	}
	if c, ok := m.Match("sub.deep.evil.com"); !ok || c != CategoryMalware {
		t.Errorf("subdomain should match parent: %v %v", c, ok)
	}
	if _, ok := m.Match("com"); ok {
		t.Error("bare TLD must never match")
	}
	if c, ok := m.Match("9.9.9.9"); !ok || c != CategoryBotnet {
		t.Errorf("ip match failed: %v %v", c, ok)
	}
	if _, ok := m.Match("good.example.org"); ok {
		t.Error("unlisted domain matched")
	}
}
