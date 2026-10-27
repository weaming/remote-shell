package identity

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestServerIdentityIsStableAcrossRestart(t *testing.T) {
	stateDir := t.TempDir()
	first, err := LoadOrCreateServer(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateServer(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("server ID changed: %q != %q", first.ID, second.ID)
	}
	if first.ID != NodeID(first.PrivateKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("server ID does not match key fingerprint: %q", first.ID)
	}
	info, err := os.Stat(filepath.Join(stateDir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("identity key permissions are too broad: %o", info.Mode().Perm())
	}
}

func TestClientPrivateKeyRequiresPrivatePermissions(t *testing.T) {
	_, privateKey, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(path, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadClientPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.PrivateKey(loaded).Equal(privateKey) {
		t.Fatal("loaded client key differs from saved key")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientPrivateKey(path); err == nil {
		t.Fatal("expected broad private-key permissions to be rejected")
	}
}

func TestClientPrivateKeyRejectsCorruptedHalves(t *testing.T) {
	_, privateKey, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 40} {
		tampered := append(ed25519.PrivateKey(nil), privateKey...)
		tampered[offset] ^= 0xFF
		path := filepath.Join(t.TempDir(), "client.key")
		if err := os.WriteFile(path, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadClientPrivateKey(path); err == nil {
			t.Fatalf("expected a corrupted key at offset %d to be rejected", offset)
		}
	}
}
