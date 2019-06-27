package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"

	"github.com/pkg/errors"
	stepx509 "github.com/smallstep/cli/pkg/x509"
	"golang.org/x/crypto/ed25519"
)

var (
	// DefaultKeyType is the default type of a private key.
	DefaultKeyType = "EC"
	// DefaultKeySize is the default size (in # of bits) of a private key.
	DefaultKeySize = 2048
	// DefaultKeyCurve is the default curve of a private key.
	DefaultKeyCurve = "P-256"
	// DefaultSignatureAlgorithm is the default signature algorithm used on a
	// certificate with the default key type.
	DefaultSignatureAlgorithm = x509.ECDSAWithSHA256
)

// PublicKey extracts a public key from a private key.
func PublicKey(priv interface{}) (interface{}, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return k, nil
	default:
		return nil, errors.Errorf("unrecognized key type: %T", priv)
	}
}

// GenerateDefaultKey generates a public/private key pair using sane defaults
// for key type, curve, and size.
func GenerateDefaultKey() (interface{}, error) {
	return GenerateKey(DefaultKeyType, DefaultKeyCurve, DefaultKeySize)
}

// GenerateKey generates a key of the given type (kty).
func GenerateKey(kty, crv string, size int) (interface{}, error) {
	switch kty {
	case "EC":
		return generateECKey(crv)
	case "RSA":
		return generateRSAKey(size)
	case "OKP":
		return generateOKPKey(crv)
	case "oct":
		return generateOctKey(size)
	default:
		return nil, errors.Errorf("unrecognized key type: %s", kty)
	}
}

// ExtractKey returns the given public or private key or extracts the public key
// if a x509.Certificate or x509.CertificateRequest is given.
func ExtractKey(in interface{}) (interface{}, error) {
	switch k := in.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return in, nil
	case []byte:
		return in, nil
	case *x509.Certificate:
		return k.PublicKey, nil
	case *x509.CertificateRequest:
		return k.PublicKey, nil
	case *stepx509.Certificate:
		return k.PublicKey, nil
	case *stepx509.CertificateRequest:
		return k.PublicKey, nil
	default:
		return nil, errors.Errorf("cannot extract the key from type '%T'", k)
	}
}

func generateECKey(crv string) (interface{}, error) {
	var c elliptic.Curve
	switch crv {
	case "P-256":
		c = elliptic.P256()
	case "P-384":
		c = elliptic.P384()
	case "P-521":
		c = elliptic.P521()
	default:
		return nil, errors.Errorf("invalid value for argument crv (crv: '%s')", crv)
	}

	key, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "error generating EC key")
	}

	return key, nil
}

func generateRSAKey(bits int) (interface{}, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.Wrap(err, "error generating RSA key")
	}

	return key, nil
}

func generateOKPKey(crv string) (interface{}, error) {
	switch crv {
	case "Ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "error generating Ed25519 key")
		}

		return key, nil
	default:
		return nil, errors.Errorf("missing or invalid value for argument 'crv'. "+
			"expected 'Ed25519', but got '%s'", crv)
	}
}

func generateOctKey(size int) (interface{}, error) {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, size)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return nil, err
		}
		result[i] = chars[num.Int64()]
	}
	return result, nil
}
