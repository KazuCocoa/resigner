package keychain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// buildSelfSignedCert creates a minimal self-signed certificate for testing.
func buildSelfSignedCert(t *testing.T, pub, priv interface{}) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// buildPEMBlocks constructs the PEM blocks the way pkcs12.ToPEM emits them:
//   - certificate block with "localKeyId" header
//   - private-key block with matching "localKeyId" header and the given DER bytes
func buildPEMBlocks(cert *x509.Certificate, keyDER []byte) []*pem.Block {
	localKeyID := "test-key-id"
	return []*pem.Block{
		{
			Type:    "CERTIFICATE",
			Headers: map[string]string{"localKeyId": localKeyID},
			Bytes:   cert.Raw,
		},
		{
			Type:    "PRIVATE KEY",
			Headers: map[string]string{"localKeyId": localKeyID},
			Bytes:   keyDER,
		},
	}
}

func TestParsePKCSBlocks_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cert := buildSelfSignedCert(t, &key.PublicKey, key)

	// pkcs12.ToPEM uses PKCS#1 DER for RSA under "PRIVATE KEY" block type.
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	blocks := buildPEMBlocks(cert, keyDER)

	certs, keys := parsePKCSBlocks(blocks)

	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d — RSA PKCS1 key was not parsed", len(keys))
	}
}

func TestParsePKCSBlocks_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cert := buildSelfSignedCert(t, &key.PublicKey, key)

	// pkcs12.ToPEM uses SEC 1 DER for ECDSA under "PRIVATE KEY" block type.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	blocks := buildPEMBlocks(cert, keyDER)

	certs, keys := parsePKCSBlocks(blocks)

	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d — ECDSA SEC1 key was not parsed (common for Apple p12 files)", len(keys))
	}
}

func TestParsePKCSBlocks_ECDSA_IdentityZipped(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cert := buildSelfSignedCert(t, &key.PublicKey, key)

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	blocks := buildPEMBlocks(cert, keyDER)
	certs, keys := parsePKCSBlocks(blocks)
	identities := zipCertsAndKeys(certs, keys)

	if len(identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(identities))
	}
	for _, id := range identities {
		if id.Certificate == nil {
			t.Fatal("identity has nil certificate")
		}
		if id.PrivateKey == nil {
			t.Fatal("identity has nil private key")
		}
	}
}
