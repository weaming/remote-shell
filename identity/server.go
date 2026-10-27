package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"remote-shell/protocol"
)

// identityFileName holds the agent's Ed25519 seed as hex, so the file is
// readable and diffable; the public half is derived on load.
const identityFileName = "identity.hex"

type ServerIdentity struct {
	ID          string
	PrivateKey  ed25519.PrivateKey
	Certificate tls.Certificate
}

// LoadOrCreateServer loads or creates the identity in stateDir, which the caller
// derives from the agent name.
func LoadOrCreateServer(stateDir string) (ServerIdentity, error) {
	if stateDir == "" {
		return ServerIdentity{}, fmt.Errorf("state directory is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return ServerIdentity{}, fmt.Errorf("create state directory: %w", err)
	}
	keyPath := filepath.Join(stateDir, identityFileName)
	privateKey, err := loadPrivateKey(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		privateKey, err = createPrivateKey(keyPath)
	}
	if err != nil {
		return ServerIdentity{}, err
	}
	certificate, err := makeCertificate(privateKey)
	if err != nil {
		return ServerIdentity{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return ServerIdentity{
		ID:          NodeID(publicKey),
		PrivateKey:  privateKey,
		Certificate: certificate,
	}, nil
}

func NodeID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "node-" + hex.EncodeToString(digest[:12])
}

func ClientID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "client-" + hex.EncodeToString(digest[:12])
}

func ServerTLSConfig(server ServerIdentity, trustedClient ed25519.PublicKey) (*tls.Config, error) {
	if len(server.Certificate.Certificate) == 0 {
		return nil, fmt.Errorf("server certificate is required")
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{protocol.Version},
		Certificates: []tls.Certificate{server.Certificate},
	}
	if len(trustedClient) == 0 {
		return config, nil
	}
	if len(trustedClient) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted client public key must be %d bytes", ed25519.PublicKeySize)
	}
	trustedClient = append(ed25519.PublicKey(nil), trustedClient...)
	config.ClientAuth = tls.RequireAnyClientCert
	config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("client certificate is required")
		}
		certificate, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse client certificate: %w", err)
		}
		publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
		if !ok || !equalBytes(publicKey, trustedClient) {
			return fmt.Errorf("client public key is not trusted")
		}
		return nil
	}
	return config, nil
}

// loadPrivateKey reads the 32-byte seed stored as hex and derives the key pair.
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s must hold a %d-character hex seed", path, ed25519.SeedSize*2)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect identity file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("identity %s must not be accessible by group or others", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func createPrivateKey(path string) (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server identity: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadPrivateKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create identity file: %w", err)
	}
	if _, err := fmt.Fprintf(file, "%s\n", hex.EncodeToString(privateKey.Seed())); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write identity seed: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync identity seed: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close identity seed: %w", err)
	}
	return privateKey, nil
}

func makeCertificate(privateKey ed25519.PrivateKey) (tls.Certificate, error) {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: NodeID(publicKey)},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse generated certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: leaf}, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
