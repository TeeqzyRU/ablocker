package firewall

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

// These tests talk to the real iptables of the machine, so they need root and
// skip themselves everywhere else. They use their own chain, never the
// production ABLOCKER_BLOCKED one.
func newTestIPTables(t *testing.T) *IPTablesFirewall {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ipt, err := iptables.New()
	if err != nil {
		t.Skipf("iptables not available: %v", err)
	}
	if _, err := ipt.List("raw", "PREROUTING"); err != nil {
		t.Skipf("raw table not available: %v", err)
	}
	const chain = "ABLOCKER_TEST"
	cleanup := func() {
		_ = ipt.Delete("raw", "PREROUTING", "-j", chain)
		_ = ipt.ClearChain("raw", chain)
		_ = ipt.DeleteChain("raw", chain)
	}
	cleanup()
	t.Cleanup(cleanup)
	return &IPTablesFirewall{
		ipRegex:   regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`),
		ipt:       ipt,
		chainName: chain,
	}
}

func rulesFor(t *testing.T, f *IPTablesFirewall, ip string) int {
	t.Helper()
	rules, err := f.ipt.List("raw", f.chainName)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rules {
		if strings.Contains(r, "-s "+ip+"/32 ") {
			n++
		}
	}
	return n
}

// Regression: BlockIP used to treat "a rule containing the IP as a substring"
// as "already blocked". With thousands of bans, an IP like 95.46.197.5 was
// silently never blocked because 95.46.197.50 (or 195.46.197.5) already was —
// the ban existed in storage, traffic kept flowing, and the detector kept
// reporting "(IP уже в бане)".
func TestBlockIPIsExactNotSubstring(t *testing.T) {
	f := newTestIPTables(t)
	for _, ip := range []string{"95.46.197.50", "195.46.197.5", "95.46.197.51"} {
		if err := f.BlockIP(ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.BlockIP("95.46.197.5"); err != nil {
		t.Fatal(err)
	}
	if n := rulesFor(t, f, "95.46.197.5"); n != 1 {
		t.Fatalf("95.46.197.5 must get its own DROP rule even when longer IPs containing it are banned, got %d rules", n)
	}

	// Blocking again must not add a duplicate.
	if err := f.BlockIP("95.46.197.5"); err != nil {
		t.Fatal(err)
	}
	if n := rulesFor(t, f, "95.46.197.5"); n != 1 {
		t.Fatalf("repeated BlockIP must not duplicate the rule, got %d", n)
	}

	got, err := f.GetBlockedIPs()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"95.46.197.5", "95.46.197.50", "195.46.197.5", "95.46.197.51"} {
		if !got[ip] {
			t.Errorf("GetBlockedIPs must report %s", ip)
		}
	}

	// Unblocking the short IP must leave the longer ones in place.
	if err := f.UnblockIP("95.46.197.5"); err != nil {
		t.Fatal(err)
	}
	if rulesFor(t, f, "95.46.197.5") != 0 || rulesFor(t, f, "95.46.197.50") != 1 {
		t.Fatal("UnblockIP must remove exactly the given IP")
	}
}
