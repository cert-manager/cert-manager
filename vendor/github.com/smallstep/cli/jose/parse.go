package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/ui"
	"golang.org/x/crypto/ed25519"
	jose "gopkg.in/square/go-jose.v2"
)

type keyType int

const (
	jwkKeyType keyType = iota
	pemKeyType
	octKeyType
)

// MaxDecryptTries is the maximum number of attempts to decrypt a file.
const MaxDecryptTries = 3

// Decrypt returns the decrypted version of the given data if it's encrypted,
// it will return the raw data if it's not encrypted or the format is not
// valid.
func Decrypt(prompt string, data []byte, opts ...Option) ([]byte, error) {
	ctx, err := new(context).apply(opts...)
	if err != nil {
		return nil, err
	}

	enc, err := jose.ParseEncrypted(string(data))
	if err != nil {
		return data, nil
	}

	// Decrypt flow
	var pass []byte
	for i := 0; i < MaxDecryptTries; i++ {
		if len(ctx.password) == 0 {
			pass, err = ui.PromptPassword(prompt, ctx.uiOptions...)
			if err != nil {
				return nil, err
			}
		} else {
			pass = ctx.password
		}

		if data, err = enc.Decrypt(pass); err == nil {
			return data, nil
		}
	}

	return nil, errors.New("failed to decrypt JWK: invalid password")
}

// ParseKey returns a JSONWebKey from the given JWK file or a PEM file. For
// password protected keys, it will ask the user for a password.
// func ParseKey(filename, use, alg, kid string, subtle bool) (*JSONWebKey, error) {
func ParseKey(filename string, opts ...Option) (*JSONWebKey, error) {
	ctx, err := new(context).apply(opts...)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}

	jwk := new(JSONWebKey)
	switch guessKeyType(ctx, b) {
	case jwkKeyType:
		// Attempt to parse an encrypted file
		prompt := fmt.Sprintf("Please enter the password to decrypt %s", filename)
		if b, err = Decrypt(prompt, b, opts...); err != nil {
			return nil, err
		}

		// Unmarshal the plain (or decrypted JWK)
		if err := json.Unmarshal(b, jwk); err != nil {
			return nil, errors.Errorf("error reading %s: unsupported format", filename)
		}
	case pemKeyType:
		jwk.Key, err = pemutil.ParseKey(b, pemutil.WithFilename(filename), pemutil.WithPassword(ctx.password))
		if err != nil {
			return nil, err
		}
	case octKeyType:
		jwk.Key = b
	}

	// Validate key id
	if ctx.kid != "" && jwk.KeyID != "" && ctx.kid != jwk.KeyID {
		return nil, errors.Errorf("kid %s does not match the kid on %s", ctx.kid, filename)
	}
	if jwk.KeyID == "" {
		jwk.KeyID = ctx.kid
	}
	if jwk.Use == "" {
		jwk.Use = ctx.use
	}

	// Set the algorithm if empty
	guessJWKAlgorithm(ctx, jwk)

	// Validate alg: if the flag '--subtle' is passed we will allow to overwrite it
	if !ctx.subtle && ctx.alg != "" && jwk.Algorithm != "" && ctx.alg != jwk.Algorithm {
		return nil, errors.Errorf("alg %s does not match the alg on %s", ctx.alg, filename)
	}
	if ctx.subtle && ctx.alg != "" {
		jwk.Algorithm = ctx.alg
	}

	return jwk, nil
}

// ReadJWKSet reads a JWK Set from a URL or filename. URLs must start with "https://".
func ReadJWKSet(filename string) ([]byte, error) {
	if strings.HasPrefix(filename, "https://") {
		resp, err := http.Get(filename)
		if err != nil {
			return nil, errors.Wrapf(err, "error retrieving %s", filename)
		}
		defer resp.Body.Close()
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "error retrieving %s", filename)
		}
		return b, nil
	}
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}
	return b, nil
}

// ParseKeySet returns the JWK with the given key after parsing a JWKSet from
// a given file.
// func ParseKeySet(filename, alg, kid string, isSubtle bool) (*jose.JSONWebKey, error) {
func ParseKeySet(filename string, opts ...Option) (*jose.JSONWebKey, error) {
	ctx, err := new(context).apply(opts...)
	if err != nil {
		return nil, err
	}

	b, err := ReadJWKSet(filename)
	if err != nil {
		return nil, err
	}

	// Attempt to parse an encrypted file
	prompt := fmt.Sprintf("Please enter the password to decrypt %s", filename)
	if b, err = Decrypt(prompt, b); err != nil {
		return nil, err
	}

	// Unmarshal the plain or decrypted JWKSet
	jwkSet := new(jose.JSONWebKeySet)
	if err := json.Unmarshal(b, jwkSet); err != nil {
		return nil, errors.Errorf("error reading %s: unsupported format", filename)
	}

	jwks := jwkSet.Key(ctx.kid)
	switch len(jwks) {
	case 0:
		return nil, errors.Errorf("cannot find key with kid %s on %s", ctx.kid, filename)
	case 1:
		jwk := &jwks[0]

		// Set the algorithm if empty
		guessJWKAlgorithm(ctx, jwk)

		// Validate alg: if the flag '--subtle' is passed we will allow the
		// overwrite of the alg
		if !ctx.subtle && ctx.alg != "" && jwk.Algorithm != "" && ctx.alg != jwk.Algorithm {
			return nil, errors.Errorf("alg %s does not match the alg on %s", ctx.alg, filename)
		}
		if ctx.subtle && ctx.alg != "" {
			jwk.Algorithm = ctx.alg
		}
		return jwk, nil
	default:
		return nil, errors.Errorf("multiple keys with kid %s have been found on %s", ctx.kid, filename)
	}
}

// guessKeyType returns the key type of the given data. Key types are JWK, PEM
// or oct.
func guessKeyType(ctx *context, data []byte) keyType {
	switch ctx.alg {
	// jwk or file with oct data
	case "HS256", "HS384", "HS512":
		// Encrypted JWK ?
		if _, err := jose.ParseEncrypted(string(data)); err == nil {
			return jwkKeyType
		}
		// JSON JWK ?
		if err := json.Unmarshal(data, &JSONWebKey{}); err == nil {
			return jwkKeyType
		}
		// Default to oct
		return octKeyType
	default:
		// PEM or default to JWK
		if bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return pemKeyType
		}
		return jwkKeyType
	}
}

// guessJWKAlgorithm set the algorithm if it's not set and we can guess it
func guessJWKAlgorithm(ctx *context, jwk *jose.JSONWebKey) {
	if jwk.Algorithm == "" {
		// Force default algorithm if passed.
		if ctx.alg != "" {
			jwk.Algorithm = ctx.alg
			return
		}

		// Guess only fixed algorithms if no defaults is enabled
		if ctx.noDefaults {
			guessKnownJWKAlgorithm(ctx, jwk)
			return
		}

		// Use defaults for each key type
		switch k := jwk.Key.(type) {
		case []byte:
			if jwk.Use == "enc" {
				jwk.Algorithm = string(DefaultOctKeyAlgorithm)
			} else {
				jwk.Algorithm = string(DefaultOctSigsAlgorithm)
			}
		case *ecdsa.PrivateKey:
			if jwk.Use == "enc" {
				jwk.Algorithm = string(DefaultECKeyAlgorithm)
			} else {
				jwk.Algorithm = getECAlgorithm(k.Curve)
			}
		case *ecdsa.PublicKey:
			if jwk.Use == "enc" {
				jwk.Algorithm = string(DefaultECKeyAlgorithm)
			} else {
				jwk.Algorithm = getECAlgorithm(k.Curve)
			}
		case *rsa.PrivateKey, *rsa.PublicKey:
			if jwk.Use == "enc" {
				jwk.Algorithm = string(DefaultRSAKeyAlgorithm)
			} else {
				jwk.Algorithm = string(DefaultRSASigAlgorithm)
			}
		// Ed25519 can only be used for signing operations
		case ed25519.PrivateKey, ed25519.PublicKey:
			jwk.Algorithm = EdDSA
		}
	}
}

// guessKnownJWKAlgorithm sets the algorithm for keys that only have one
// possible algorithm.
func guessKnownJWKAlgorithm(ctx *context, jwk *jose.JSONWebKey) {
	if jwk.Algorithm == "" && jwk.Use != "enc" {
		switch k := jwk.Key.(type) {
		case *ecdsa.PrivateKey:
			jwk.Algorithm = getECAlgorithm(k.Curve)
		case *ecdsa.PublicKey:
			jwk.Algorithm = getECAlgorithm(k.Curve)
		case ed25519.PrivateKey, ed25519.PublicKey:
			jwk.Algorithm = EdDSA
		}
	}
}

// getECAlgorithm returns the JWA algorithm name for the given elliptic curve.
// If the curve is not supported it will return an empty string.
//
// Supported curves are P-256, P-384, and P-521.
func getECAlgorithm(crv elliptic.Curve) string {
	switch crv.Params().Name {
	case P256:
		return ES256
	case P384:
		return ES384
	case P521:
		return ES512
	default:
		return ""
	}
}
