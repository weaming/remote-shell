package discovery

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/weaming/zeroconf"
	"remote-shell/protocol"
)

type Node struct {
	ID       string
	Name     string
	Protocol string
	// Hostname is the per-agent mDNS host record; SystemHost is the machine's
	// own host name from TXT, which is what tells a client it is local.
	Hostname     string
	SystemHost   string
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
			values[key] = unescapeTXT(value)
		}
	}
	authRequired, _ := strconv.ParseBool(values["auth"])
	node := Node{
		ID:           values["id"],
		Name:         values["name"],
		Protocol:     values["proto"],
		Hostname:     strings.TrimSuffix(entry.HostName, "."),
		SystemHost:   values["host"],
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

// unescapeTXT decodes the DNS presentation escapes a TXT value can carry.
// Advertisers publish plain UTF-8, but a TXT record stores raw bytes and the
// resolver hands them back escaped, so a Chinese name arrives as "\229\174\191".
func unescapeTXT(value string) string {
	if !strings.ContainsRune(value, '\\') {
		return value
	}
	decoded := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char != '\\' || index+1 >= len(value) {
			decoded = append(decoded, char)
			continue
		}
		// DNS escapes are three decimal digits, \229 for byte 0xE5.
		if index+3 < len(value) && isDecimalDigit(value[index+1]) && isDecimalDigit(value[index+2]) && isDecimalDigit(value[index+3]) {
			code := (value[index+1]-'0')*100 + (value[index+2]-'0')*10 + (value[index+3] - '0')
			decoded = append(decoded, code)
			index += 3
			continue
		}
		index++
		decoded = append(decoded, value[index])
	}
	return string(decoded)
}

func isDecimalDigit(char byte) bool {
	return char >= '0' && char <= '9'
}
