package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

// ValidateJWK validates the given JWK.
func ValidateJWK(jwk *JSONWebKey) error {
	switch jwk.Use {
	case "sig":
		return validateSigJWK(jwk)
	case "enc":
		return validateEncJWK(jwk)
	default:
		return validateGeneric(jwk)
	}
}

// validateSigJWK validates the given JWK for signature operations.
func validateSigJWK(jwk *JSONWebKey) error {
	if jwk.Algorithm == "" {
		return errors.New("flag '--alg' is required with the given key")
	}
	errctx := "the given key"

	switch k := jwk.Key.(type) {
	case []byte:
		switch jwk.Algorithm {
		case HS256, HS384, HS512:
			return nil
		}
		errctx = "kty 'oct'"
	case *rsa.PrivateKey, *rsa.PublicKey:
		switch jwk.Algorithm {
		case RS256, RS384, RS512:
			return nil
		case PS256, PS384, PS512:
			return nil
		}
		errctx = "kty 'RSA'"
	case *ecdsa.PrivateKey:
		curve := k.Params().Name
		switch {
		case jwk.Algorithm == ES256 && curve == P256:
			return nil
		case jwk.Algorithm == ES384 && curve == P384:
			return nil
		case jwk.Algorithm == ES512 && curve == P521:
			return nil
		}
		errctx = fmt.Sprintf("kty 'EC' and crv '%s'", curve)
	case *ecdsa.PublicKey:
		curve := k.Params().Name
		switch {
		case jwk.Algorithm == ES256 && curve == P256:
			return nil
		case jwk.Algorithm == ES384 && curve == P384:
			return nil
		case jwk.Algorithm == ES512 && curve == P521:
			return nil
		}
		errctx = fmt.Sprintf("kty 'EC' and crv '%s'", curve)
	case ed25519.PrivateKey, ed25519.PublicKey:
		if jwk.Algorithm == EdDSA {
			return nil
		}
		errctx = "kty 'OKP' and crv 'Ed25519'"
	}

	return errors.Errorf("alg '%s' is not compatible with %s", jwk.Algorithm, errctx)
}

// validatesEncJWK validates the given JWK for encryption operations.
func validateEncJWK(jwk *JSONWebKey) error {
	alg := KeyAlgorithm(jwk.Algorithm)
	var kty string

	switch jwk.Key.(type) {
	case []byte:
		switch alg {
		case DIRECT, A128GCMKW, A192GCMKW, A256GCMKW, A128KW, A192KW, A256KW:
			return nil
		}
		kty = "oct"
	case *rsa.PrivateKey, *rsa.PublicKey:
		switch alg {
		case RSA1_5, RSA_OAEP, RSA_OAEP_256:
			return nil
		}
		kty = "RSA"
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		switch alg {
		case ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW:
			return nil
		}
		kty = "EC"
	case ed25519.PrivateKey, ed25519.PublicKey:
		return errors.New("key Ed25519 cannot be used for encryption")
	}

	return errors.Errorf("alg '%s' is not compatible with kty '%s'", jwk.Algorithm, kty)
}

// validateGeneric validates just the supported key types.
func validateGeneric(jwk *JSONWebKey) error {
	switch jwk.Key.(type) {
	case []byte:
		return nil
	case *rsa.PrivateKey, *rsa.PublicKey:
		return nil
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return nil
	case ed25519.PrivateKey, ed25519.PublicKey:
		return nil
	}

	return errors.Errorf("unsupported key type '%T'", jwk.Key)
}
