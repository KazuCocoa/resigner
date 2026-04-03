package keychain

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	sha256Simd "github.com/minio/sha256-simd"

	"golang.org/x/crypto/pkcs12"
)

func CertificateFingerprint(cert *x509.Certificate) string {
	h := sha256Simd.New()
	h.Write(cert.Raw)
	return hex.EncodeToString(h.Sum(nil))
}

type Identity struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
}

type Keychain interface {
	Identities(ctx context.Context) ([]string, error)
	Identity(ctx context.Context, fingerprint string) (Identity, bool, error)
}

func KeyForCert(ctx context.Context, kc Keychain, cert *x509.Certificate) (crypto.Signer, bool, error) {
	id, found, err := kc.Identity(ctx, CertificateFingerprint(cert))
	if err != nil || !found {
		return nil, found, err
	}
	return id.PrivateKey, true, nil
}

type LocalKeychain struct {
	identities map[string]Identity
}

func LocalKeychainFromPKCS12(data []byte, password string) (*LocalKeychain, error) {
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, err
	}

	certs, keys := parsePKCSBlocks(blocks)
	identities := zipCertsAndKeys(certs, keys)

	return &LocalKeychain{identities: identities}, nil
}

func parsePKCSBlocks(blocks []*pem.Block) (map[string]blockCert, map[string]crypto.Signer) {
	certs := make(map[string]blockCert)
	keys := make(map[string]crypto.Signer)

	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs[CertificateFingerprint(c)] = blockCert{
					localKeyID: block.Headers["localKeyId"],
					cert:       c,
				}
			}
		case "PRIVATE KEY":
			// pkcs12.ToPEM emits "PRIVATE KEY" with PKCS#1 bytes for RSA
			// and SEC 1 bytes for ECDSA. Try both parsers.
			if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				keys[block.Headers["localKeyId"]] = k
			} else if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				keys[block.Headers["localKeyId"]] = k
			}
		}
	}

	return certs, keys
}

type blockCert struct {
	localKeyID string
	cert       *x509.Certificate
}

func zipCertsAndKeys(certs map[string]blockCert, keys map[string]crypto.Signer) map[string]Identity {
	identities := make(map[string]Identity)

	for fingerprint, cert := range certs {
		if key, exists := keys[cert.localKeyID]; exists {
			identities[fingerprint] = Identity{
				Certificate: cert.cert,
				PrivateKey:  key,
			}
		}
	}

	return identities
}

func (k *LocalKeychain) Identities(ctx context.Context) ([]string, error) {
	fps := make([]string, 0, len(k.identities))
	for fp := range k.identities {
		fps = append(fps, fp)
	}
	return fps, nil
}

func (k *LocalKeychain) Identity(ctx context.Context, fingerprint string) (Identity, bool, error) {
	id, found := k.identities[fingerprint]
	return id, found, nil
}

func MultiKeychain(keychains ...Keychain) Keychain {
	return compositeKeychain(keychains)
}

type compositeKeychain []Keychain

func (c compositeKeychain) Identities(ctx context.Context) ([]string, error) {
	var all []string
	for _, kc := range c {
		ids, err := kc.Identities(ctx)
		if err != nil {
			return nil, err
		}
		all = append(all, ids...)
	}
	return all, nil
}

func (c compositeKeychain) Identity(ctx context.Context, fingerprint string) (Identity, bool, error) {
	for _, kc := range c {
		id, found, err := kc.Identity(ctx, fingerprint)
		if err != nil {
			return Identity{}, false, err
		}
		if found {
			return id, true, nil
		}
	}
	return Identity{}, false, nil
}
