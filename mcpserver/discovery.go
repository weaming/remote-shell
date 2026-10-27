package mcpserver

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"remote-shell/discovery"
)

// cachedNode is one discovered agent, merged across the addresses it advertises
// for its interfaces.
type cachedNode struct {
	ID           string
	Name         string
	Instance     string
	Hostname     string
	AuthRequired bool
	Addresses    []string
}

// nodeCache holds the last discovery result until a connection fails, and
// remembers which address last answered for each node, so repeated calls skip
// the lookup and try the known good address first.
type nodeCache struct {
	mu         sync.Mutex
	nodes      []cachedNode
	fetched    time.Time
	lastGood   map[string]string
	refreshing bool
	wait       chan struct{}
}

func newNodeCache() *nodeCache {
	return &nodeCache{lastGood: make(map[string]string, 4)}
}

func (c *nodeCache) get() []cachedNode {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.nodes)
}

func (c *nodeCache) set(nodes []cachedNode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes = nodes
	c.fetched = time.Now()
}

// invalidate drops the cached result so the next lookup searches again.
func (c *nodeCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes = nil
	c.fetched = time.Time{}
}

// remember records the address that just answered for a node.
func (c *nodeCache) remember(nodeID, address string) {
	if nodeID == "" || address == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastGood[nodeID] = address
}

// preferred orders a node's addresses with the last working one first.
func (c *nodeCache) preferred(node cachedNode) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	addresses := slices.Clone(node.Addresses)
	address, ok := c.lastGood[node.ID]
	if !ok {
		return addresses
	}
	for index, candidate := range addresses {
		if candidate == address {
			addresses[0], addresses[index] = addresses[index], addresses[0]
			break
		}
	}
	return addresses
}

// chooseNode picks the only discovered agent, and refuses to guess between
// several.
func chooseNode(nodes []cachedNode) (cachedNode, error) {
	switch len(nodes) {
	case 0:
		return cachedNode{}, fmt.Errorf("no agent discovered on the local network; start one or pass node as host:port")
	case 1:
		return nodes[0], nil
	default:
		described := make([]string, 0, len(nodes))
		for _, node := range nodes {
			address := ""
			if len(node.Addresses) > 0 {
				address = node.Addresses[0]
			}
			described = append(described, fmt.Sprintf("%s (%s)", labelOf(node), address))
		}
		return cachedNode{}, fmt.Errorf("%d agents discovered, pass node explicitly: %s",
			len(nodes), strings.Join(described, ", "))
	}
}

// browseNodes collects announcements for the configured discovery window.
func (s *Server) browseNodes(ctx context.Context) ([]cachedNode, error) {
	return s.browseNodesFor(ctx, s.config.DiscoveryWait)
}

// browseOnce runs the configured lookup, or the injected one used by tests.
func (s *Server) browseOnce(ctx context.Context) ([]cachedNode, error) {
	if s.browse != nil {
		return s.browse(ctx)
	}
	return s.browseNodes(ctx)
}

// browseNodesFor collects announcements for an explicit window.
func (s *Server) browseNodesFor(ctx context.Context, wait time.Duration) ([]cachedNode, error) {
	browseCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	stream, err := discovery.Browse(browseCtx)
	if err != nil {
		return nil, fmt.Errorf("start mDNS discovery: %w", err)
	}
	merged := make(map[string]*cachedNode)
	var order []string
	for {
		select {
		case <-browseCtx.Done():
			nodes := make([]cachedNode, 0, len(order))
			for _, id := range order {
				nodes = append(nodes, *merged[id])
			}
			return nodes, nil
		case node, ok := <-stream:
			if !ok {
				stream = nil
				continue
			}
			entry, seen := merged[node.ID]
			if !seen {
				entry = &cachedNode{
					ID:           node.ID,
					Name:         node.Name,
					Instance:     node.Instance,
					Hostname:     node.Hostname,
					AuthRequired: node.AuthRequired,
				}
				merged[node.ID] = entry
				order = append(order, node.ID)
			}
			for _, address := range node.Addresses {
				if !slices.Contains(entry.Addresses, address) {
					entry.Addresses = append(entry.Addresses, address)
				}
			}
		}
	}
}

// knownNodes returns the cached discovery result, searching the network only
// when nothing is cached. The result stays valid until a connection to it fails
// and the cache is invalidated.
func (s *Server) knownNodes(ctx context.Context) ([]cachedNode, error) {
	if nodes := s.discovery.get(); len(nodes) > 0 {
		return nodes, nil
	}
	return s.searchNodes(ctx)
}

// searchNodes browses the network once, sharing the result with concurrent
// callers instead of browsing twice.
func (s *Server) searchNodes(ctx context.Context) ([]cachedNode, error) {
	s.discovery.mu.Lock()
	if s.discovery.refreshing {
		wait := s.discovery.wait
		s.discovery.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return s.discovery.get(), nil
	}
	s.discovery.refreshing = true
	s.discovery.wait = make(chan struct{})
	s.discovery.mu.Unlock()

	nodes, err := s.browseOnce(ctx)

	s.discovery.mu.Lock()
	if err == nil {
		s.discovery.nodes = nodes
		s.discovery.fetched = time.Now()
	}
	s.discovery.refreshing = false
	close(s.discovery.wait)
	s.discovery.mu.Unlock()

	if err != nil {
		return nil, err
	}
	logDiscovered(nodes)
	return nodes, nil
}

// logDiscovered reports one line per search, so the log shows when the bridge
// found agents and which one it will use by default.
func logDiscovered(nodes []cachedNode) {
	switch len(nodes) {
	case 0:
		log.Printf("mDNS discovery found no agent")
	case 1:
		log.Printf("mDNS discovery found %s; using it whenever node is omitted", describeNodes(nodes))
	default:
		log.Printf("mDNS discovery found %d agents (%s); node must be given explicitly",
			len(nodes), describeNodes(nodes))
	}
}

// labelOf prefers the human-readable name and falls back to the node ID.
func labelOf(node cachedNode) string {
	if node.Name != "" {
		return node.Name + " " + node.ID
	}
	return node.ID
}

// describeNodes lists "id@address" pairs for logging.
func describeNodes(nodes []cachedNode) string {
	parts := make([]string, 0, len(nodes))
	for _, node := range nodes {
		address := ""
		if len(node.Addresses) > 0 {
			address = node.Addresses[0]
		}
		parts = append(parts, labelOf(node)+"@"+address)
	}
	return strings.Join(parts, ", ")
}
