package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"remote-shell/agent"
)

func TestKeygenDefaultsToRepositoryKeysDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := runKeygen(nil); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join("keys", "client.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestWantsHelp(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "-help"} {
		if !wantsHelp([]string{"--listen", arg}) {
			t.Errorf("wantsHelp did not recognize %q", arg)
		}
	}
	if wantsHelp([]string{"--listen", ":42424"}) {
		t.Fatal("wantsHelp recognized a non-help option")
	}
}

func TestResolveMCPMode(t *testing.T) {
	cases := []struct {
		name     string
		explicit map[string]bool
		want     string
	}{
		{name: "default", explicit: map[string]bool{}, want: "stdio"},
		{name: "listen selects http", explicit: map[string]bool{"listen": true}, want: "http"},
		{name: "token selects http", explicit: map[string]bool{"auth-token": true}, want: "http"},
		{name: "other flags keep stdio", explicit: map[string]bool{"node": true, "client-key": true}, want: "stdio"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := resolveMCPMode(testCase.explicit); got != testCase.want {
				t.Fatalf("mode = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestAllowUnauthenticatedOverridesEmbeddedKey(t *testing.T) {
	original := agent.EmbeddedTrustedClientPublicKeyHex
	agent.EmbeddedTrustedClientPublicKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	defer func() { agent.EmbeddedTrustedClientPublicKeyHex = original }()

	config, handled, err := resolveServeConfig([]string{"--allow-unauthenticated", "--no-discovery"})
	if err != nil || handled {
		t.Fatalf("embedded key must not conflict with --allow-unauthenticated: err=%v handled=%v", err, handled)
	}
	if !config.AllowUnauthenticated {
		t.Fatal("authentication was not disabled")
	}
	if len(config.TrustedClientKey) != 0 {
		t.Fatalf("embedded key survived --allow-unauthenticated: %x", config.TrustedClientKey)
	}
}

func TestResolveServeConfigProxySources(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://env-proxy.example:8080")

	fromEnvironment, _, err := resolveServeConfig([]string{"--allow-unauthenticated"})
	if err != nil {
		t.Fatal(err)
	}
	if fromEnvironment.ProxyURL != "http://env-proxy.example:8080" {
		t.Fatalf("proxy from HTTPS_PROXY = %q", fromEnvironment.ProxyURL)
	}

	fromFlag, _, err := resolveServeConfig([]string{"--allow-unauthenticated", "--proxy", "http://flag-proxy.example:8081"})
	if err != nil {
		t.Fatal(err)
	}
	if fromFlag.ProxyURL != "http://flag-proxy.example:8081" {
		t.Fatalf("--proxy did not take precedence: %q", fromFlag.ProxyURL)
	}
}

func TestExplicitClientKeyConflictsWithAllowUnauthenticated(t *testing.T) {
	_, _, err := resolveServeConfig([]string{
		"--allow-unauthenticated",
		"--client-public-key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("explicit key with disabled authentication must be rejected: %v", err)
	}
}

func TestExplicitEmptyClientKeyAllowsUnauthenticated(t *testing.T) {
	config, _, err := resolveServeConfig([]string{"--allow-unauthenticated", "--client-public-key", ""})
	if err != nil {
		t.Fatalf("an explicitly empty key must not conflict: %v", err)
	}
	if !config.AllowUnauthenticated || len(config.TrustedClientKey) != 0 {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestResolveServeConfigReachesAgentValidation(t *testing.T) {
	original := agent.EmbeddedTrustedClientPublicKeyHex
	agent.EmbeddedTrustedClientPublicKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	defer func() { agent.EmbeddedTrustedClientPublicKeyHex = original }()

	// Proves the conflict check is passed before agent-level validation runs,
	// even when a key is embedded in the binary.
	_, _, err := resolveServeConfig([]string{"--allow-unauthenticated", "--max-streams", "99999"})
	if err != nil {
		t.Fatalf("resolveServeConfig must not validate limits: %v", err)
	}
	if _, err := agent.New(agent.Config{AllowUnauthenticated: true, DisableDiscovery: true, MaxConcurrentStreams: 99999, Name: "test-agent", StateBaseDir: t.TempDir()}); err == nil {
		t.Fatal("expected the agent to reject an oversized stream limit")
	}
}
