package agentreach

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
)

// One slow connection must not block another (audit P17).
func TestCacheEntriesLockIndependently(t *testing.T) {
	a, b := &cacheEntry{}, &cacheEntry{}
	release := make(chan struct{})
	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.get(func() []*posture.Snapshot { close(started); <-release; return []*posture.Snapshot{{Host: "a"}} })
	}()
	<-started
	done := make(chan []*posture.Snapshot)
	go func() { done <- b.get(func() []*posture.Snapshot { return []*posture.Snapshot{{Host: "b"}} }) }()
	select {
	case got := <-done:
		if got[0].Host != "b" {
			t.Fatalf("got %q", got[0].Host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("entry b waited for entry a's collection")
	}
	close(release)
	wg.Wait()
	calls := 0
	a.get(func() []*posture.Snapshot { calls++; return nil })
	if calls != 0 {
		t.Error("a fresh entry was collected again within the TTL")
	}
}

// Collection runs on its own bounded context, so a cancelled query cannot
// leave a truncated snapshot in the cache (audit P17).
func TestLiveCollectIgnoresQueryContext(t *testing.T) {
	saved := collect
	defer func() { collect = saved }()
	var sawErr error
	var sawDeadline bool
	collect = func(ctx context.Context, _ posture.Options) *posture.Snapshot {
		sawErr = ctx.Err()
		_, sawDeadline = ctx.Deadline()
		return &posture.Snapshot{Host: "x"}
	}
	queryCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = queryCtx
	if s := liveCollect(posture.Options{}); s.Host != "x" || sawErr != nil || !sawDeadline {
		t.Fatalf("collection context: err=%v deadline=%v", sawErr, sawDeadline)
	}
}
