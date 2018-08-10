package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func GenerateRSAPrivateKey(keySize int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keySize)
}

func EncodePKCS1PrivateKey(pk *rsa.PrivateKey) []byte {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)}

	return pem.EncodeToMemory(block)
}

// PublicKeyMatchesCertificate can be used to verify the given public key
// is the correct counter-part to the given x509 Certificate.
// It will return false and no error if the public key is *not* valid for the
// given Certificate.
// It will return true if the public key *is* valid for the given Certificate.
// It will return an error if either of the passed parameters are of an
// unrecognised type (i.e. non RSA/ECDSA)
func PublicKeyMatchesCertificate(check crypto.PublicKey, crt *x509.Certificate) (bool, error) {
	switch pub := crt.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaCheck, ok := check.(*rsa.PublicKey)
		if !ok {
			return false, nil
		}
		if pub.N.Cmp(rsaCheck.N) != 0 {
			return false, nil
		}
		return true, nil
	case *ecdsa.PublicKey:
		ecdsaCheck, ok := check.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		if pub.X.Cmp(ecdsaCheck.X) != 0 || pub.Y.Cmp(ecdsaCheck.Y) != 0 {
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("unrecognised Certificate public key type")
	}
}
