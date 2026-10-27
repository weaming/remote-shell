package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	"remote-shell/protocol"
)

func LoadClientPrivateKey(path string) (ed25519.PrivateKey, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client private key: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("client private key must be %d bytes", ed25519.PrivateKeySize)
	}
	if err := validateKeyPair(ed25519.PrivateKey(key)); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect client private key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("client private key %s must not be accessible by group or others", path)
	}
	return ed25519.PrivateKey(key), nil
}

// validateKeyPair rejects key files whose embedded public half does not match
// the seed, which would otherwise only fail during a TLS handshake.
func validateKeyPair(privateKey ed25519.PrivateKey) error {
	derived := ed25519.NewKeyFromSeed(privateKey.Seed()).Public().(ed25519.PublicKey)
	if !equalBytes(derived, privateKey.Public().(ed25519.PublicKey)) {
		return fmt.Errorf("private key is corrupted: public half does not match its seed")
	}
	return nil
}

func GenerateClientKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client identity: %w", err)
	}
	return publicKey, privateKey, nil
}

// ClientTLSConfig intentionally skips server identity verification per the current design.
func ClientTLSConfig(privateKey ed25519.PrivateKey) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{protocol.Version},
		InsecureSkipVerify: true,
	}
	if len(privateKey) == 0 {
		return config, nil
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("client private key must be %d bytes", ed25519.PrivateKeySize)
	}
	certificate, err := makeClientCertificate(privateKey)
	if err != nil {
		return nil, err
	}
	config.Certificates = []tls.Certificate{certificate}
	return config, nil
}

func makeClientCertificate(privateKey ed25519.PrivateKey) (tls.Certificate, error) {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate client certificate serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: ClientID(publicKey)},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create client certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse client certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: leaf}, nil
}
