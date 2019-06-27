package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"golang.org/x/crypto/ed25519"
)

const (
	jwksUsageSig = "sig"
	jwksUsageEnc = "enc"
	// defaultKeyType is the default type of the one-time token key.
	defaultKeyType = EC
	// defaultKeyCurve is the default curve of the one-time token key.
	defaultKeyCurve = P256
	// defaultKeyAlg is the default algorithm of the one-time token key.
	defaultKeyAlg = ES256
	// defaultKeySize is the default size of the one-time token key.
	defaultKeySize = 0
)

var (
	errAmbiguousCertKeyUsage = errors.New("jose/generate: certificate's key usage is ambiguous, it should be for signature or encipherment, but not both (use --subtle to ignore usage field)")
	errNoCertKeyUsage        = errors.New("jose/generate: certificate doesn't contain any key usage (use --subtle to ignore usage field)")
)

// GenerateDefaultKeyPair generates an asymmetric public/private key pair.
// Returns the public key as a JWK and the private key as an encrypted JWE.
func GenerateDefaultKeyPair(pass []byte) (*JSONWebKey, *JSONWebEncryption, error) {
	if len(pass) == 0 {
		return nil, nil, errors.New("step-jose: password cannot be empty when encryptying a JWK")
	}

	// Generate the OTT key
	jwk, err := GenerateJWK(defaultKeyType, defaultKeyCurve, defaultKeyAlg, jwksUsageSig, "", defaultKeySize)
	if err != nil {
		return nil, nil, err
	}

	// The thumbprint is computed from the public key
	hash, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error generating JWK thumbprint")
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(hash)

	b, err := json.Marshal(jwk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error marshaling JWK")
	}

	// Encrypt private key using PBES2
	salt, err := randutil.Salt(PBKDF2SaltSize)
	if err != nil {
		return nil, nil, err
	}
	recipient := Recipient{
		Algorithm:  PBES2_HS256_A128KW,
		Key:        pass,
		PBES2Count: PBKDF2Iterations,
		PBES2Salt:  salt,
	}

	opts := new(EncrypterOptions)
	opts.WithContentType(ContentType("jwk+json"))

	encrypter, err := NewEncrypter(DefaultEncAlgorithm, recipient, opts)
	if err != nil {
		return nil, nil, errs.Wrap(err, "error creating cipher")
	}

	jwe, err := encrypter.Encrypt(b)
	if err != nil {
		return nil, nil, errs.Wrap(err, "error encrypting data")
	}

	public := jwk.Public()
	return &public, jwe, nil
}

// GenerateJWK generates a JWK given the key type, curve, alg, use, kid and
// the size of the RSA or oct keys if necessary.
func GenerateJWK(kty, crv, alg, use, kid string, size int) (jwk *JSONWebKey, err error) {
	switch kty {
	case "EC":
		return generateECKey(crv, alg, use, kid)
	case "RSA":
		return generateRSAKey(size, alg, use, kid)
	case "OKP":
		return generateOKPKey(crv, alg, use, kid)
	case "oct":
		return generateOctKey(size, alg, use, kid)
	default:
		return nil, errors.Errorf("missing or invalid value for flag '--kty'")
	}
}

// GenerateJWKFromPEM returns an incomplete JSONWebKey using the key from a
// PEM file.
func GenerateJWKFromPEM(filename string, subtle bool) (*JSONWebKey, error) {
	key, err := pemutil.Read(filename)
	if err != nil {
		return nil, err
	}

	switch key := key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		return &JSONWebKey{
			Key: key,
		}, nil
	case *ecdsa.PrivateKey, *ecdsa.PublicKey, ed25519.PrivateKey, ed25519.PublicKey:
		return &JSONWebKey{
			Key:       key,
			Algorithm: algForKey(key),
		}, nil
	case *x509.Certificate:
		var use string
		if !subtle {
			use, err = keyUsageForCert(key)
			if err != nil {
				return nil, err
			}
		}
		return &JSONWebKey{
			Key:          key.PublicKey,
			Certificates: []*x509.Certificate{key},
			Algorithm:    algForKey(key.PublicKey),
			Use:          use,
		}, nil
	default:
		return nil, errors.Errorf("error parsing %s: unsupported key type '%T'", filename, key)
	}
}

func algForKey(key crypto.PublicKey) string {
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		return getECAlgorithm(key.Curve)
	case *ecdsa.PublicKey:
		return getECAlgorithm(key.Curve)
	case ed25519.PrivateKey, ed25519.PublicKey:
		return EdDSA
	default:
		return ""
	}
}

func keyUsageForCert(cert *x509.Certificate) (string, error) {
	isDigitalSignature := containsUsage(cert.KeyUsage,
		x509.KeyUsageDigitalSignature,
		x509.KeyUsageContentCommitment,
		x509.KeyUsageCertSign,
		x509.KeyUsageCRLSign,
	)
	isEncipherment := containsUsage(cert.KeyUsage,
		x509.KeyUsageKeyEncipherment,
		x509.KeyUsageDataEncipherment,
		x509.KeyUsageKeyAgreement,
		x509.KeyUsageEncipherOnly,
		x509.KeyUsageDecipherOnly,
	)
	if isDigitalSignature && isEncipherment {
		return "", errAmbiguousCertKeyUsage
	}
	if isDigitalSignature {
		return jwksUsageSig, nil
	}
	if isEncipherment {
		return jwksUsageEnc, nil
	}
	return "", errNoCertKeyUsage
}

func containsUsage(usage x509.KeyUsage, queries ...x509.KeyUsage) bool {
	for _, query := range queries {
		if usage&query == query {
			return true
		}
	}
	return false
}

func generateECKey(crv, alg, use, kid string) (*JSONWebKey, error) {
	var c elliptic.Curve
	var sigAlg string
	switch crv {
	case P256, "": // default
		c, sigAlg = elliptic.P256(), ES256
	case P384:
		c, sigAlg = elliptic.P384(), ES384
	case P521:
		c, sigAlg = elliptic.P521(), ES512
	default:
		return nil, errors.Errorf("missing or invalid value for flag '--crv'")
	}

	key, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "error generating ECDSA key")
	}

	switch use {
	case "enc":
		if alg == "" {
			alg = string(DefaultECKeyAlgorithm)
		}
	default:
		if alg == "" {
			alg = sigAlg
		}
	}

	return &JSONWebKey{
		Key:       key,
		Algorithm: alg,
		Use:       use,
		KeyID:     kid,
	}, nil
}

func generateRSAKey(bits int, alg, use, kid string) (*JSONWebKey, error) {
	if bits == 0 {
		bits = DefaultRSASize
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.Wrap(err, "error generating RSA key")
	}

	switch use {
	case "enc":
		if alg == "" {
			alg = string(DefaultRSAKeyAlgorithm)
		}
	default:
		if alg == "" {
			alg = DefaultRSASigAlgorithm
		}
	}

	return &JSONWebKey{
		Key:       key,
		Algorithm: alg,
		Use:       use,
		KeyID:     kid,
	}, nil
}

func generateOKPKey(crv, alg, use, kid string) (*JSONWebKey, error) {
	switch crv {
	case Ed25519, "": // default
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "error generating Ed25519 key")
		}

		switch use {
		case "enc":
			return nil, errors.New("invalid algorithm: Ed25519 cannot be used for encryption")
		default:
			if alg == "" {
				alg = EdDSA
			}
		}

		return &JSONWebKey{
			Key:       key,
			Algorithm: alg,
			Use:       use,
			KeyID:     kid,
		}, nil
	default:
		return nil, errors.Errorf("missing or invalid value for flag '--crv'")
	}
}

func generateOctKey(size int, alg, use, kid string) (*JSONWebKey, error) {
	if size == 0 {
		size = DefaultOctSize
	}

	key, err := randutil.Alphanumeric(size)
	if err != nil {
		return nil, err
	}

	switch use {
	case "enc":
		if alg == "" {
			alg = string(DefaultOctKeyAlgorithm)
		}
	default:
		if alg == "" {
			alg = string(DefaultOctSigsAlgorithm)
		}
	}

	return &JSONWebKey{
		Key:       []byte(key),
		Algorithm: alg,
		Use:       use,
		KeyID:     kid,
	}, nil
}
