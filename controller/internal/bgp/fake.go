package bgp

import (
	"context"
	"sync"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
)

// FakeSpeaker records every call; tests assert on Calls and drive errors
// via Err on the chosen method. Safe for concurrent engine workers.
type FakeSpeaker struct {
	mu       sync.Mutex
	Calls    []string
	Rules    []flowspec.Rule
	Prefixes []string
	Err      error
	Started  bool
	States   []PeerState
}

func (f *FakeSpeaker) record(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, call)
	return f.Err
}

func (f *FakeSpeaker) CallsOf(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		if c == prefix {
			n++
		}
	}
	return n
}

func (f *FakeSpeaker) Start(_ context.Context) error { f.Started = true; return f.record("start") }
func (f *FakeSpeaker) Stop(_ context.Context) error  { return f.record("stop") }

func (f *FakeSpeaker) AnnounceFlowspec(_ context.Context, rule flowspec.Rule) error {
	f.mu.Lock()
	f.Rules = append(f.Rules, rule)
	f.mu.Unlock()
	return f.record("announce_flowspec")
}

func (f *FakeSpeaker) WithdrawFlowspec(_ context.Context, rule flowspec.Rule) error {
	f.mu.Lock()
	f.Rules = append(f.Rules, rule)
	f.mu.Unlock()
	return f.record("withdraw_flowspec")
}

func (f *FakeSpeaker) AnnounceBlackhole(_ context.Context, prefix string) error {
	f.mu.Lock()
	f.Prefixes = append(f.Prefixes, prefix)
	f.mu.Unlock()
	return f.record("announce_blackhole")
}

func (f *FakeSpeaker) WithdrawBlackhole(_ context.Context, prefix string) error {
	f.mu.Lock()
	f.Prefixes = append(f.Prefixes, prefix)
	f.mu.Unlock()
	return f.record("withdraw_blackhole")
}

func (f *FakeSpeaker) SyncPeers(_ context.Context, peers []Peer) error {
	for range peers {
	}
	return f.record("sync_peers")
}

func (f *FakeSpeaker) PeerStates(_ context.Context) []PeerState { return f.States }
