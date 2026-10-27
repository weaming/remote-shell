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
	entry.Text = []string{"id=node-a", "name=mini-garden", "proto=remote-shell/1", "auth=true"}
	entry.AddrIPv4 = []net.IP{net.ParseIP("192.168.1.4")}
	node, ok := parseEntry(entry)
	if !ok {
		t.Fatal("expected a valid discovered node")
	}
	if node.ID != "node-a" || node.Name != "mini-garden" || node.Hostname != "host.local" || !node.AuthRequired {
		t.Fatalf("unexpected node metadata: %+v", node)
	}
	if len(node.Addresses) != 1 || node.Addresses[0] != "192.168.1.4:42424" {
		t.Fatalf("unexpected node addresses: %#v", node.Addresses)
	}
}

// A non-ASCII name comes back from the resolver DNS-escaped; it must be decoded
// so discovery shows the text the operator configured.
func TestParseEntryDecodesEscapedName(t *testing.T) {
	entry := zeroconf.NewServiceEntry("RemoteShell-node-a", "_remote-shell._udp", "local.")
	entry.Port = 42424
	entry.Text = []string{"id=node-a", `name=\229\174\191\228\184\187`, "proto=remote-shell/1"}
	entry.AddrIPv4 = []net.IP{net.ParseIP("192.168.1.4")}
	node, ok := parseEntry(entry)
	if !ok {
		t.Fatal("expected a valid discovered node")
	}
	if node.Name != "宿主" {
		t.Fatalf("name = %q, want the decoded text", node.Name)
	}
}

func TestUnescapeTXTDecodesOnlyRealEscapes(t *testing.T) {
	cases := map[string]string{
		"build-box":    "build-box",
		`C:\\tmp`:      `C:\tmp`,
		`a\\b`:         `a\b`,
		"":             "",
		`\229\174\191`: "宿",
		`\032`:         " ",
	}
	for input, want := range cases {
		if got := unescapeTXT(input); got != want {
			t.Errorf("unescapeTXT(%q) = %q, want %q", input, got, want)
		}
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
