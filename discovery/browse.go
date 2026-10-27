package discovery

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
	"remote-shell/protocol"
)

type Node struct {
	ID           string
	Protocol     string
	Hostname     string
	Instance     string
	Addresses    []string
	AuthRequired bool
}

func Browse(ctx context.Context) (<-chan Node, error) {
	resolver, err := zeroconf.NewResolver()
	if err != nil {
		return nil, err
	}
	entries := make(chan *zeroconf.ServiceEntry, 32)
	if err := resolver.Browse(ctx, protocol.ServiceType, "local.", entries); err != nil {
		return nil, err
	}
	nodes := make(chan Node, 16)
	go func() {
		defer close(nodes)
		const (
			maxSeenEntries = 4096
			seenTTL        = 5 * time.Minute
		)
		seen := make(map[string]time.Time)
		prune := func(now time.Time) {
			for key, lastSeen := range seen {
				if now.Sub(lastSeen) > seenTTL {
					delete(seen, key)
				}
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case entry, ok := <-entries:
				if !ok {
					return
				}
				node, ok := parseEntry(entry)
				if !ok || node.Protocol != protocol.Version {
					continue
				}
				now := time.Now()
				prune(now)
				for _, address := range node.Addresses {
					key := node.ID + "@" + address
					if _, duplicate := seen[key]; duplicate {
						seen[key] = now
						continue
					}
					if len(seen) >= maxSeenEntries {
						continue
					}
					seen[key] = now
					candidate := node
					candidate.Addresses = []string{address}
					select {
					case nodes <- candidate:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return nodes, nil
}

func parseEntry(entry *zeroconf.ServiceEntry) (Node, bool) {
	if entry == nil || entry.Port < 1 || entry.Port > 65535 {
		return Node{}, false
	}
	values := make(map[string]string, len(entry.Text))
	for _, item := range entry.Text {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			values[key] = value
		}
	}
	authRequired, _ := strconv.ParseBool(values["auth"])
	node := Node{
		ID:           values["id"],
		Protocol:     values["proto"],
		Hostname:     strings.TrimSuffix(entry.HostName, "."),
		Instance:     entry.Instance,
		AuthRequired: authRequired,
	}
	for _, address := range entry.AddrIPv4 {
		node.Addresses = append(node.Addresses, net.JoinHostPort(address.String(), strconv.Itoa(entry.Port)))
	}
	for _, address := range entry.AddrIPv6 {
		node.Addresses = append(node.Addresses, net.JoinHostPort(address.String(), strconv.Itoa(entry.Port)))
	}
	return node, node.ID != "" && len(node.Addresses) > 0
}
