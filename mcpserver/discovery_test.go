package mcpserver

import (
	"strings"
	"testing"
	"time"
)

func TestChooseNodeRefusesAmbiguity(t *testing.T) {
	if _, err := chooseNode(nil); err == nil {
		t.Fatal("expected an error when nothing was discovered")
	}
	only := cachedNode{ID: "node-a", Addresses: []string{"127.0.0.1:42424"}}
	node, err := chooseNode([]cachedNode{only})
	if err != nil || node.ID != "node-a" {
		t.Fatalf("chooseNode(single) = %v, %v", node, err)
	}
	_, err = chooseNode([]cachedNode{only, {ID: "node-b", Addresses: []string{"10.0.0.2:42424"}}})
	if err == nil {
		t.Fatal("expected an error for two discovered agents")
	}
	for _, want := range []string{"node-a", "node-b", "127.0.0.1:42424"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

func TestNodeCachePrefersLastWorkingAddress(t *testing.T) {
	cache := newNodeCache()
	stored := cachedNode{ID: "node-a", Addresses: []string{"10.0.0.1:42424", "10.0.0.2:42424"}}
	cache.set([]cachedNode{stored})

	if got := cache.get(); len(got) != 1 || got[0].ID != "node-a" {
		t.Fatalf("get() = %v, want the stored node", got)
	}
	cache.remember("node-a", "10.0.0.2:42424")
	if got := cache.preferred(stored); got[0] != "10.0.0.2:42424" {
		t.Fatalf("preferred = %v, want the last working address first", got)
	}
	other := cachedNode{ID: "node-b", Addresses: []string{"10.1.0.1:42424"}}
	if got := cache.preferred(other); got[0] != "10.1.0.1:42424" {
		t.Fatalf("preferred unrelated = %v, want the original order", got)
	}
	// Remembering must not reorder the cached node itself.
	if got := stored.Addresses[0]; got != "10.0.0.1:42424" {
		t.Fatalf("stored addresses were mutated: %v", stored.Addresses)
	}
}

// The cache has no time limit: only a failed connection drops it.
func TestNodeCacheKeepsResultUntilInvalidated(t *testing.T) {
	cache := newNodeCache()
	cache.set([]cachedNode{{ID: "node-a"}})
	time.Sleep(20 * time.Millisecond)
	if got := cache.get(); len(got) != 1 {
		t.Fatalf("get() = %v, want the result to survive without a TTL", got)
	}
	cache.invalidate()
	if got := cache.get(); len(got) != 0 {
		t.Fatalf("get() after invalidate = %v, want empty", got)
	}
}
