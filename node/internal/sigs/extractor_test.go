package sigs

import (
	"math/rand"
	"net"
	"testing"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
)

// makeSample builds a Sample with the given destination IP and payload.
func makeSample(dst string, payload []byte) Sample {
	return Sample{DstIP: net.ParseIP(dst).To4(), Payload: payload}
}

func TestExtractorNoSignatureWithTooFewSamples(t *testing.T) {
	e := &Extractor{}
	// Fill attack payloads with a strong pattern but too few samples (< 256).
	attackPayload := make([]byte, 64)
	attackPayload[10] = 0xAA
	for i := 0; i < 100; i++ {
		e.AddAttack(makeSample("10.0.0.1", attackPayload))
	}
	if got := e.Extract(); got != nil {
		t.Fatalf("expected no signature with too few samples, got %+v", got)
	}
}

func TestExtractorFindsSignature(t *testing.T) {
	e := &Extractor{}

	// Attack: byte at offset 10 is always 0xAA, bytes 11-13 are 0xBB 0xCC 0xDD.
	attackPayload := make([]byte, 64)
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		copy(p, attackPayload)
		p[10] = 0xAA
		p[11] = 0xBB
		p[12] = 0xCC
		p[13] = 0xDD
		// Vary other bytes slightly to avoid accidental baseline matches.
		p[0] = byte(i)
		e.AddAttack(makeSample("10.0.0.1", p))
	}

	// Baseline: byte at offset 10 is random, never 0xAA.
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		p[10] = byte(rand.Intn(254) + 1) // avoid 0x00 and 0xAA by chance
		if p[10] == 0xAA {
			p[10] = 0x00
		}
		e.AddBaseline(makeSample("10.0.0.1", p))
	}

	sig := e.Extract()
	if sig == nil {
		t.Fatal("expected a signature to be extracted")
	}
	if sig.Action != bpf.FilterActionDrop {
		t.Fatalf("expected DROP action, got %d", sig.Action)
	}
	t.Logf("signature: offset=%d len=%d pattern=0x%x mask=0x%x",
		sig.Offset, sig.Len, sig.Pattern, sig.Mask)
}

func TestExtractorFindsContiguousSignature(t *testing.T) {
	e := &Extractor{}

	// Attack: bytes at offsets 10,11,12,13 are fixed: AA BB CC DD.
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		p[10] = 0xAA
		p[11] = 0xBB
		p[12] = 0xCC
		p[13] = 0xDD
		e.AddAttack(makeSample("10.0.0.1", p))
	}

	// Baseline: bytes at offsets 10-13 are fixed to values different from attack.
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		p[10] = 0x00
		p[11] = 0x11
		p[12] = 0x22
		p[13] = 0x33
		e.AddBaseline(makeSample("10.0.0.1", p))
	}

	sig := e.Extract()
	if sig == nil {
		t.Fatal("expected a signature to be extracted")
	}
	if sig.Offset != 10 {
		t.Fatalf("expected offset 10, got %d", sig.Offset)
	}
	if sig.Len < 4 {
		t.Fatalf("expected len >= 4, got %d", sig.Len)
	}
	// Verify pattern contains the expected bytes at the right positions.
	for i := 0; i < int(sig.Len); i++ {
		shift := uint(i * 8)
		got := byte(sig.Pattern >> shift & 0xFF)
		expected := byte([]byte{0xAA, 0xBB, 0xCC, 0xDD}[i])
		if got != expected {
			t.Fatalf("pattern byte %d: expected 0x%02X, got 0x%02X", i, expected, got)
		}
	}
	// Mask should have 0xFF for significant bytes.
	for i := 0; i < int(sig.Len); i++ {
		shift := uint(i * 8)
		if byte(sig.Mask>>shift&0xFF) != 0xFF {
			t.Fatalf("mask byte %d: expected 0xFF, got 0x%02X", i, byte(sig.Mask>>shift&0xFF))
		}
	}
}

func TestExtractorBaselineRejection(t *testing.T) {
	e := &Extractor{}

	// Attack: byte at offset 20 is 0x42 in 100% of attack samples.
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		p[20] = 0x42
		e.AddAttack(makeSample("10.0.0.2", p))
	}

	// Baseline: byte at offset 20 is 0x42 in 50% of baseline samples (> 1%).
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		if i%2 == 0 {
			p[20] = 0x42
		}
		e.AddBaseline(makeSample("10.0.0.2", p))
	}

	// No contiguous run of 4+ significant positions (only offset 20 is
	// potentially significant but baseline rejects it).
	sig := e.Extract()
	if sig != nil {
		t.Fatalf("expected no signature due to baseline contamination, got %+v", sig)
	}
}

func TestExtractorAttackThreshold(t *testing.T) {
	e := &Extractor{}

	// Attack: byte at offset 30 is 0x99 in only 50% of samples (< 85%).
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		if i%2 == 0 {
			p[30] = 0x99
		}
		e.AddAttack(makeSample("10.0.0.3", p))
	}

	// Baseline: all zeros (different from attack bytes 50-59).
	for i := 0; i < 300; i++ {
		e.AddBaseline(makeSample("10.0.0.5", make([]byte, 64)))
	}

	sig := e.Extract()
	if sig != nil {
		t.Fatalf("expected no signature due to low attack frequency, got %+v", sig)
	}
}

func TestExtractorMinPatternLength(t *testing.T) {
	e := &Extractor{}

	// Attack: only 2 consecutive significant bytes (below MinPatternLen=4).
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		p[40] = 0x11
		p[41] = 0x22
		e.AddAttack(makeSample("10.0.0.4", p))
	}
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		e.AddBaseline(makeSample("10.0.0.4", p))
	}

	sig := e.Extract()
	if sig != nil {
		t.Fatalf("expected no signature (run too short), got %+v", sig)
	}
}

func TestExtractorMaxPatternLength(t *testing.T) {
	e := &Extractor{}

	// Attack: 10 consecutive significant bytes — should cap at MaxPatternLen=8.
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		for j := 50; j < 60; j++ {
			p[j] = byte(j)
		}
		e.AddAttack(makeSample("10.0.0.5", p))
	}
	for i := 0; i < 300; i++ {
		p := make([]byte, 64)
		e.AddBaseline(makeSample("10.0.0.5", p))
	}

	sig := e.Extract()
	if sig == nil {
		t.Fatal("expected a signature")
	}
	if sig.Len > MaxPatternLen {
		t.Fatalf("len %d exceeds MaxPatternLen %d", sig.Len, MaxPatternLen)
	}
}

func TestExtractorReset(t *testing.T) {
	e := &Extractor{}
	attackPayload := make([]byte, 64)
	attackPayload[7] = 0xFF
	for i := 0; i < 300; i++ {
		e.AddAttack(makeSample("10.0.0.6", attackPayload))
	}
	for i := 0; i < 300; i++ {
		e.AddBaseline(makeSample("10.0.0.6", make([]byte, 64)))
	}

	at, bl := e.Len()
	if at != 300 || bl != 300 {
		t.Fatalf("expected 300/300 samples, got %d/%d", at, bl)
	}

	e.Reset()
	at, bl = e.Len()
	if at != 0 || bl != 0 {
		t.Fatalf("expected 0/0 after reset, got %d/%d", at, bl)
	}
}
