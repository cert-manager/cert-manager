package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	MinRSAKeySize = 2048
	MaxRSAKeySize = 8192

	ECCurve256 = 256
	ECCurve384 = 384
	ECCurve521 = 521
)

func GeneratePrivateKeyForCertificate(crt *v1alpha1.Certificate) (crypto.PrivateKey, error) {
	switch crt.Spec.KeyAlgorithm {
	case v1alpha1.KeyAlgorithm(""), v1alpha1.RSAKeyAlgorithm:
		keySize := MinRSAKeySize

		if crt.Spec.KeySize > 0 {
			keySize = crt.Spec.KeySize
		}

		return GenerateRSAPrivateKey(keySize)
	case v1alpha1.ECDSAKeyAlgorithm:
		keySize := ECCurve256

		if crt.Spec.KeySize > 0 {
			keySize = crt.Spec.KeySize
		}

		return GenerateECPrivateKey(keySize)
	default:
		return nil, fmt.Errorf("unsupported private key algorithm specified: %s", crt.Spec.KeyAlgorithm)
	}
}

func GenerateRSAPrivateKey(keySize int) (*rsa.PrivateKey, error) {
	// Do not allow keySize < 2048
	// https://en.wikipedia.org/wiki/Key_size#cite_note-twirl-14
	if keySize < MinRSAKeySize {
		return nil, fmt.Errorf("weak rsa key size specified: %d. minimum key size: %d", keySize, MinRSAKeySize)
	}
	if keySize > MaxRSAKeySize {
		return nil, fmt.Errorf("rsa key size specified too big: %d. maximum key size: %d", keySize, MaxRSAKeySize)
	}

	return rsa.GenerateKey(rand.Reader, keySize)
}

func GenerateECPrivateKey(keySize int) (*ecdsa.PrivateKey, error) {
	var ecCurve elliptic.Curve

	switch keySize {
	case ECCurve256:
		ecCurve = elliptic.P256()
	case ECCurve384:
		ecCurve = elliptic.P384()
	case ECCurve521:
		ecCurve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ecdsa key size specified: %d", keySize)
	}

	return ecdsa.GenerateKey(ecCurve, rand.Reader)
}

func EncodePrivateKey(pk crypto.PrivateKey) ([]byte, error) {
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		return EncodePKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		return EncodeECPrivateKey(k)
	default:
		return nil, fmt.Errorf("error encoding private key: unknown key type: %T", pk)
	}
}

func EncodePKCS1PrivateKey(pk *rsa.PrivateKey) []byte {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)}

	return pem.EncodeToMemory(block)
}

func EncodeECPrivateKey(pk *ecdsa.PrivateKey) ([]byte, error) {
	asnBytes, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("error encoding private key: %s", err.Error())
	}

	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: asnBytes}
	return pem.EncodeToMemory(block), nil
}

func PublicKeyForPrivateKey(pk crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		return k.Public(), nil
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unknown private key type: %T", pk)
	}
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
