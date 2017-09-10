package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func GenerateRSAPrivateKey(keySize int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keySize)
}

func EncodePKCS1PrivateKey(pk *rsa.PrivateKey) []byte {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)}

	return pem.EncodeToMemory(block)
}
