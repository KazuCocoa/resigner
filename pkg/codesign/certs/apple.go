package certs

import (
	"crypto/x509"
	_ "embed"
)

// NOTE: Apple certificates need periodic updates. Current expiration dates:
// - AppleRootCA.pem: Feb 9, 2035
// - AppleDevCA.pem: Feb 7, 2023 (EXPIRED)
// - AppleDevCAG3.pem: Feb 20, 2030
//
// To update certificates:
// 1. Download from https://www.apple.com/certificateauthority/
// 2. Convert DER to PEM:
//    openssl x509 -inform DER -in AppleDevCA.cer -out AppleDevCA.pem
//    openssl x509 -inform DER -in AppleDevCAG3.cer -out AppleDevCAG3.pem
//    openssl x509 -inform DER -in AppleRootCA.cer -out AppleRootCA.pem
// 3. Replace files in this directory
// 4. Run: go test ./...

//go:embed AppleDevCA.pem
var AppleDevCA []byte

//go:embed AppleDevCAG3.pem
var AppleDevCAG3 []byte

//go:embed AppleRootCA.pem
var AppleRootCA []byte

func IntermediatePool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	pool.AppendCertsFromPEM(AppleDevCA)
	pool.AppendCertsFromPEM(AppleDevCAG3)

	return pool, nil
}

func RootPool() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}

	pool.AppendCertsFromPEM(AppleRootCA)

	return pool, nil
}
