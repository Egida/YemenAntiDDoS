package dns

import (
	"net"
	"testing"
	"time"
)

func TestSplitLabels(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"example.com", []string{"example", "com"}},
		{"a.b.example.com", []string{"a", "b", "example", "com"}},
		{"a.b.example.com.", []string{"a", "b", "example", "com"}},
		{"single", []string{"single"}},
	}
	for _, tt := range tests {
		got := splitLabels(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("splitLabels(%q): got %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitLabels(%q): got %v, want %v", tt.in, got, tt.want)
				break
			}
		}
	}
}

func TestParentZone(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"a.example.com", "example.com"},
		{"x7y9z2.example.com", "example.com"},
		{"a.b.example.com", "example.com"},
		{"com", "com"},
	}
	for _, tt := range tests {
		got := parentZone(tt.in)
		if got != tt.want {
			t.Errorf("parentZone(%q): got %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	// Constant string has zero entropy.
	if e := shannonEntropy("aaaa"); e != 0 {
		t.Errorf("constant string entropy: got %f, want 0", e)
	}
	// "ab" has 1 bit of entropy.
	if e := shannonEntropy("ab"); e < 0.99 || e > 1.01 {
		t.Errorf("'ab' entropy: got %f, want ~1", e)
	}
	// Random-looking string has high entropy.
	if e := shannonEntropy("x7y9z2k3m8"); e < 3.0 {
		t.Errorf("high-entropy string: got %f, want >3", e)
	}
}

func TestIsRandomLabel(t *testing.T) {
	// Short labels are never random.
	if IsRandomLabel("abc") {
		t.Errorf("short label 'abc' should not be random")
	}
	// Low entropy label is not random.
	if IsRandomLabel("aaaaaaaa") {
		t.Errorf("low-entropy label should not be random")
	}
	// High entropy long label is random.
	if !IsRandomLabel("x7y9z2k3m8pq") {
		t.Errorf("high-entropy label should be random")
	}
}

func TestAnalyzerObserveQuery(t *testing.T) {
	a := NewAnalyzer()
	// Need >= MinQueriesForEvaluation queries for a report to be emitted.
	for i := 0; i < 10; i++ {
		q := &DNSQuery{
			QName:     "x7y9z2k3m8pq" + string(rune('a'+i)) + ".example.com",
			QType:     1,
			QClass:    1,
			SrcIP:     net.ParseIP("10.0.0.1"),
			DstIP:     net.ParseIP("10.0.0.53"),
			SrcPort:   12345,
			DstPort:   53,
			Timestamp: time.Now(),
		}
		a.ObserveQuery(q)
	}

	reports := a.ZoneReports()
	if len(reports) != 1 {
		t.Fatalf("expected 1 zone report, got %d", len(reports))
	}
	if reports[0].Zone != "example.com" {
		t.Errorf("expected zone example.com, got %s", reports[0].Zone)
	}
	if reports[0].Queries != 10 {
		t.Errorf("expected 10 queries, got %d", reports[0].Queries)
	}
	if reports[0].HighEntropyLabel != 10 {
		t.Errorf("expected 10 high entropy labels, got %d", reports[0].HighEntropyLabel)
	}
}

func TestAnalyzerObserveResponseNXDOMAIN(t *testing.T) {
	a := NewAnalyzer()

	// Send 20 queries with high-entropy random subdomains of example.com.
	for i := 0; i < 20; i++ {
		a.ObserveQuery(&DNSQuery{
			QName:     "x7y9z2k3m8pq" + string(rune('a'+i)) + ".example.com",
			QType:     1,
			SrcIP:     net.ParseIP("10.0.0.1"),
			DstIP:     net.ParseIP("10.0.0.53"),
			Timestamp: time.Now(),
		})
	}

	// Send 10 NXDOMAIN responses (50% ratio).
	for i := 0; i < 10; i++ {
		a.ObserveResponse(&DNSResponse{
			QName:     "example.com",
			RCode:     3, // NXDOMAIN
			SrcIP:     net.ParseIP("10.0.0.53"),
			DstIP:     net.ParseIP("10.0.0.1"),
			Timestamp: time.Now(),
		})
	}

	// Send 10 NOERROR responses.
	for i := 0; i < 10; i++ {
		a.ObserveResponse(&DNSResponse{
			QName:     "example.com",
			RCode:     0, // NOERROR
			SrcIP:     net.ParseIP("10.0.0.53"),
			DstIP:     net.ParseIP("10.0.0.1"),
			Timestamp: time.Now(),
		})
	}

	reports := a.ZoneReports()
	if len(reports) != 1 {
		t.Fatalf("expected 1 zone report, got %d", len(reports))
	}
	r := reports[0]
	if r.Queries != 20 {
		t.Errorf("expected 20 queries, got %d", r.Queries)
	}
	if r.NXDOMAIN != 10 {
		t.Errorf("expected 10 NXDOMAIN, got %d", r.NXDOMAIN)
	}
	if r.NXDOMAINRatio < 0.49 || r.NXDOMAINRatio > 0.51 {
		t.Errorf("expected NXDOMAIN ratio ~0.5, got %f", r.NXDOMAINRatio)
	}
	if r.HighEntropyRatio < 0.9 {
		t.Errorf("expected high entropy ratio >0.9, got %f", r.HighEntropyRatio)
	}
	if !r.IsWaterTorture {
		t.Errorf("expected Water Torture detected (50%% NXDOMAIN + high entropy)")
	}
}

func TestAnalyzerNoWaterTortureBelowThreshold(t *testing.T) {
	a := NewAnalyzer()

	// Send 20 queries with low NXDOMAIN ratio.
	for i := 0; i < 20; i++ {
		a.ObserveQuery(&DNSQuery{
			QName:     "www.example.com",
			QType:     1,
			SrcIP:     net.ParseIP("10.0.0.1"),
			DstIP:     net.ParseIP("10.0.0.53"),
			Timestamp: time.Now(),
		})
	}

	// Only 2 NXDOMAIN out of 20 (10% ratio, below 40% threshold).
	for i := 0; i < 2; i++ {
		a.ObserveResponse(&DNSResponse{
			QName:     "example.com",
			RCode:     3,
			SrcIP:     net.ParseIP("10.0.0.53"),
			DstIP:     net.ParseIP("10.0.0.1"),
			Timestamp: time.Now(),
		})
	}

	reports := a.ZoneReports()
	if len(reports) != 1 {
		t.Fatalf("expected 1 zone report (20 queries), got %d", len(reports))
	}
	if reports[0].IsWaterTorture {
		t.Errorf("expected NOT Water Torture (10%% NXDOMAIN, low entropy)")
	}
	if reports[0].NXDOMAINRatio < 0.09 || reports[0].NXDOMAINRatio > 0.11 {
		t.Errorf("expected NXDOMAIN ratio ~0.1, got %f", reports[0].NXDOMAINRatio)
	}
}

func TestZoneHashDeterministic(t *testing.T) {
	h1 := ZoneHash("example.com")
	h2 := ZoneHash("example.com")
	if h1 != h2 {
		t.Errorf("ZoneHash not deterministic: %d vs %d", h1, h2)
	}
	if h1 == ZoneHash("other.com") {
		t.Errorf("ZoneHash should differ for different domains")
	}
}

func TestZoneHashTrailingDot(t *testing.T) {
	h1 := ZoneHash("example.com")
	h2 := ZoneHash("example.com.")
	if h1 != h2 {
		t.Errorf("ZoneHash should ignore trailing dot: %d vs %d", h1, h2)
	}
}
