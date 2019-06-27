package jose

import (
	"crypto"
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
)

// Thumbprint computes the JWK Thumbprint of a key using SHA256 as the hash
// algorithm. It returns the hash encoded in the Base64 raw url encoding.
func Thumbprint(jwk *JSONWebKey) (string, error) {
	hash, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.Wrap(err, "error generating JWK thumbprint")
	}
	return base64.RawURLEncoding.EncodeToString(hash), nil
}

// EncryptJWK returns the given JWK encrypted with the default encryption
// algorithm (PBES2-HS256+A128KW).
func EncryptJWK(jwk *JSONWebKey) (*JSONWebEncryption, error) {
	key, err := ui.PromptPassword("Please enter the password to encrypt the private JWK")
	if err != nil {
		return nil, errors.Wrap(err, "error reading password")
	}

	salt, err := randutil.Salt(PBKDF2SaltSize)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(jwk)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling JWK")
	}

	// Encrypt private key using PBES2
	recipient := Recipient{
		Algorithm:  PBES2_HS256_A128KW,
		Key:        key,
		PBES2Count: PBKDF2Iterations,
		PBES2Salt:  salt,
	}

	opts := new(EncrypterOptions)
	opts.WithContentType(ContentType("jwk+json"))

	encrypter, err := NewEncrypter(DefaultEncAlgorithm, recipient, opts)
	if err != nil {
		return nil, errs.Wrap(err, "error creating cipher")
	}

	jwe, err := encrypter.Encrypt(b)
	if err != nil {
		return nil, errs.Wrap(err, "error encrypting data")
	}

	return jwe, nil
}
