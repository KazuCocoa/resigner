package utils

import (
	"crypto"

	sha256Simd "github.com/minio/sha256-simd"
)

func init() {
	crypto.RegisterHash(crypto.SHA256, sha256Simd.New)
}
