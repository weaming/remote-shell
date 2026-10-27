package discovery

import (
	"net"
	"testing"

	"github.com/grandcat/zeroconf"
)

func TestParseEntry(t *testing.T) {
	entry := zeroconf.NewServiceEntry("RemoteShell-node-a", "_remote-shell._udp", "local.")
	entry.Port = 42424
	entry.HostName = "host.local."
	entry.Text = []string{"id=node-a", "proto=remote-shell/1", "auth=true"}
	entry.AddrIPv4 = []net.IP{net.ParseIP("192.168.1.4")}
	node, ok := parseEntry(entry)
	if !ok {
		t.Fatal("expected a valid discovered node")
	}
	if node.ID != "node-a" || node.Hostname != "host.local" || !node.AuthRequired {
		t.Fatalf("unexpected node metadata: %+v", node)
	}
	if len(node.Addresses) != 1 || node.Addresses[0] != "192.168.1.4:42424" {
		t.Fatalf("unexpected node addresses: %#v", node.Addresses)
	}
}

func TestParseEntryRejectsMissingAddress(t *testing.T) {
	entry := zeroconf.NewServiceEntry("RemoteShell-node-a", "_remote-shell._udp", "local.")
	entry.Port = 42424
	entry.Text = []string{"id=node-a", "proto=remote-shell/1"}
	if _, ok := parseEntry(entry); ok {
		t.Fatal("expected an entry without addresses to be rejected")
	}
}
