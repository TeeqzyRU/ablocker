package utils

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"ablocker/config"
	"ablocker/fanout"
	"ablocker/storage"
)

func TestParseDestPort(t *testing.T) {
	cases := []struct {
		line string
		host string
		port int
	}{
		{`2026/10/14 22:15:30.561650 from 176.0.0.1:50834 accepted tcp:44.215.223.155:443 [LT_inbound >> DIRECT] email: 1`, "44.215.223.155", 443},
		{`2026/10/14 22:29:22.483840 from tcp:176.0.0.1:50898 accepted udp:17.253.38.35:123 [LT_inbound >> DIRECT] email: 1`, "17.253.38.35", 123},
		{`2026/10/14 22:31:44.293452 from 176.0.0.1:50997 accepted tcp:142.251.1.95:443 [LT_inbound -> GEM_inbound-out] email: 1`, "142.251.1.95", 443},
		{`2026/10/01 14:22:27.233276 from 176.0.0.1:62965 accepted tcp:www.gstatic.com:443 [LT_inbound >> DIRECT] email: 1`, "www.gstatic.com", 443},
		{`2026/08/18 10:49:53.964547 from 31.0.0.1:5916 accepted tcp:203.0.113.156:6881 [DE >> DIRECT] email: 1`, "203.0.113.156", 6881},
		{`x from 1.2.3.4:5 accepted tcp:[2a00:1450::1]:51413 [in >> out] email: 1`, "2a00:1450::1", 51413},
		{`malformed line`, "", 0},
	}
	for _, c := range cases {
		h, p := parseDest(c.line)
		if h != c.host || p != c.port {
			t.Errorf("parseDest(%q) = %q,%d; want %q,%d", c.line, h, p, c.host, c.port)
		}
	}
}

// line renders one access.log line in Xray's format. Client IPs use the
// documentation ranges and user IDs are fictional: no real customer data.
func line(user, src, proto, dst string, port int) string {
	from := src + ":40000"
	if proto == "udp" {
		from = "tcp:" + from // Xray logs UDP-over-TCP this way
	}
	return fmt.Sprintf("2026/10/25 12:11:38.000000 from %s accepted %s:%s:%d [LT_inbound >> DIRECT] email: %s",
		from, proto, dst, port, user)
}

// replayCorpus mixes the three traffic shapes seen in the real incidents.
func replayCorpus() []string {
	var lines []string

	// 100001 — ordinary iPhone user (shape taken from real logs): Apple, Google,
	// Cloudflare bursts on 443, push on 5223, NTP, STUN for a call, an XMPP
	// service, a Tencent service on 8991 and a few game servers on 27015.
	for i := 0; i < 400; i++ {
		lines = append(lines,
			line("100001", "198.51.100.10", "tcp", fmt.Sprintf("17.253.39.%d", 130+i%20), 443),
			line("100001", "198.51.100.10", "tcp", fmt.Sprintf("104.21.%d.%d", i%90, i%250), 443),
			line("100001", "198.51.100.10", "tcp", fmt.Sprintf("142.250.%d.%d", i%30, i%200), 443),
		)
	}
	lines = append(lines,
		line("100001", "198.51.100.10", "tcp", "17.57.146.29", 5223),
		line("100001", "198.51.100.10", "udp", "17.253.38.35", 123),
		line("100001", "198.51.100.10", "udp", "74.125.250.129", 19302),
		line("100001", "198.51.100.10", "udp", "162.159.207.0", 3478),
		line("100001", "198.51.100.10", "tcp", "198.51.100.50", 5222), // XMPP service
		line("100001", "198.51.100.10", "tcp", "198.51.100.60", 8991), // app on a custom port
		line("100001", "198.51.100.10", "tcp", "www.gstatic.com", 443),
	)
	for i := 0; i < 12; i++ {
		lines = append(lines, line("100001", "198.51.100.10", "udp", fmt.Sprintf("155.133.248.%d", 10+i), 27015))
	}

	// 100002 — a long voice/video call (looks like P2P at first glance):
	// hundreds of connections, but to the same couple of relays.
	for i := 0; i < 300; i++ {
		lines = append(lines,
			line("100002", "198.51.100.20", "udp", "74.125.250.129", 19302),
			line("100002", "198.51.100.20", "udp", "192.0.2.213", 3480), // call relay
			line("100002", "198.51.100.20", "udp", "192.0.2.213", 51234),
		)
	}

	// 100003 — encrypted BitTorrent (shape of a confirmed case): a swarm of distinct
	// peers on 6881 / 51413 / random high ports, TCP and uTP over UDP.
	ports := []int{6881, 51413, 41150, 33436, 24077, 63931, 15271, 1369, 54496, 25661}
	for i := 0; i < 230; i++ {
		proto := "tcp"
		if i%3 == 0 {
			proto = "udp"
		}
		lines = append(lines, line("100003", "203.0.113.50", proto,
			fmt.Sprintf("%d.%d.%d.%d", 31+i%150, (i*7)%250+1, (i*13)%250+1, i%250+1), ports[i%len(ports)]))
	}
	return lines
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func runFanout(lines []string) {
	for _, l := range lines {
		if dst, port := parseDest(l); dst != "" {
			handleFanout(l, dst, port)
		}
	}
}

func TestFanoutReplayLogMode(t *testing.T) {
	config.FanoutAction = "log"
	config.FanoutWindow = "10m"
	config.BypassIPSet = map[string]struct{}{}
	config.BypassNets = nil
	fanoutDetector = fanout.New(150, 10*time.Minute, nil)
	defer func() { fanoutDetector = nil }()
	buf := captureLog(t)

	runFanout(replayCorpus())

	out := buf.String()
	if n := strings.Count(out, "FANOUT: user=100003 ip=203.0.113.50"); n != 1 {
		t.Fatalf("torrent user must be reported exactly once, got %d:\n%s", n, out)
	}
	for _, u := range []string{"100001", "100002"} {
		if strings.Contains(out, "user="+u) {
			t.Errorf("user %s (normal traffic / voice call) must not be reported:\n%s", u, out)
		}
	}
	if strings.Contains(out, "blocked for") {
		t.Error("log mode must never ban")
	}
}

func TestFanoutReplayBanMode(t *testing.T) {
	store, err := storage.NewIPStorage(t.TempDir(), func(string, time.Duration, string) {})
	if err != nil {
		t.Fatal(err)
	}
	prevStore := ipStorage
	ipStorage = store
	defer func() { ipStorage = prevStore }()

	config.FanoutAction = "ban"
	config.FanoutWindow = "10m"
	config.BlockDuration = 43200
	config.BypassIPSet = map[string]struct{}{}
	_, bypass, _ := net.ParseCIDR("192.0.2.0/24") // e.g. a CDN edge subnet
	config.BypassNets = []*net.IPNet{bypass}
	fanoutDetector = fanout.New(150, 10*time.Minute, nil)
	defer func() { fanoutDetector = nil; config.BypassNets = nil }()
	buf := captureLog(t)

	corpus := replayCorpus()
	// Same torrent shape again, but arriving through a whitelisted (CDN) IP.
	for _, l := range corpus {
		if strings.Contains(l, "email: 100003") {
			corpus = append(corpus, strings.NewReplacer("203.0.113.50", "192.0.2.7", "email: 100003", "email: 100004").Replace(l))
		}
	}
	runFanout(corpus)

	out := buf.String()
	if !strings.Contains(out, "User 100003 with IP: 203.0.113.50 blocked for 43200 minutes (torrent) [fanout:") {
		t.Fatalf("torrent user must be banned with a (torrent) line:\n%s", out)
	}
	if !store.IsBlocked("203.0.113.50") {
		t.Error("banned IP must be persisted in storage")
	}
	if store.IsBlocked("192.0.2.7") {
		t.Error("whitelisted IP must never be banned")
	}
	if !strings.Contains(out, "FANOUT: user=100004 ip=192.0.2.7") || !strings.Contains(out, "BypassIPS") {
		t.Errorf("whitelisted torrent user must still be reported (so the account can be disabled):\n%s", out)
	}
	for _, ip := range []string{"198.51.100.10", "198.51.100.20"} {
		if store.IsBlocked(ip) {
			t.Errorf("%s (normal / voice) must not be banned", ip)
		}
	}
}
