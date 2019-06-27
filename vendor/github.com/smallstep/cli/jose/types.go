// Code generated (comment to force golint to ignore this file). DO NOT EDIT.

package jose

import (
	"errors"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// SupportsPBKDF2 constant to know if the underlaying library supports
// password based cryptography algorithms.
const SupportsPBKDF2 = true

// PBKDF2SaltSize is the default size of the salt for PBKDF2, 128-bit salt.
const PBKDF2SaltSize = 16

// PBKDF2Iterations is the default number of iterations for PBKDF2, 100k
// iterations. Nist recommends at least 10k, 1Passsword uses 100k.
const PBKDF2Iterations = 100000

// JSONWebSignature represents a signed JWS object after parsing.
type JSONWebSignature = jose.JSONWebSignature

// JSONWebToken represents a JSON Web Token (as specified in RFC7519).
type JSONWebToken = jwt.JSONWebToken

// JSONWebKey represents a public or private key in JWK format.
type JSONWebKey = jose.JSONWebKey

// JSONWebKeySet represents a JWK Set object.
type JSONWebKeySet = jose.JSONWebKeySet

// JSONWebEncryption represents an encrypted JWE object after parsing.
type JSONWebEncryption = jose.JSONWebEncryption

// Recipient represents an algorithm/key to encrypt messages to.
type Recipient = jose.Recipient

// EncrypterOptions represents options that can be set on new encrypters.
type EncrypterOptions = jose.EncrypterOptions

// Encrypter represents an encrypter which produces an encrypted JWE object.
type Encrypter = jose.Encrypter

// ContentType represents type of the contained data.
type ContentType = jose.ContentType

// KeyAlgorithm represents a key management algorithm.
type KeyAlgorithm = jose.KeyAlgorithm

// ContentEncryption represents a content encryption algorithm.
type ContentEncryption = jose.ContentEncryption

// SignatureAlgorithm represents a signature (or MAC) algorithm.
type SignatureAlgorithm = jose.SignatureAlgorithm

// ErrCryptoFailure indicates an error in a cryptographic primitive.
var ErrCryptoFailure = jose.ErrCryptoFailure

// Claims represents public claim values (as specified in RFC 7519).
type Claims = jwt.Claims

// Builder is a utility for making JSON Web Tokens. Calls can be chained, and
// errors are accumulated until the final call to CompactSerialize/FullSerialize.
type Builder = jwt.Builder

// NumericDate represents date and time as the number of seconds since the
// epoch, including leap seconds. Non-integer values can be represented
// in the serialized format, but we round to the nearest second.
type NumericDate = jwt.NumericDate

// Audience represents the recipients that the token is intended for.
type Audience = jwt.Audience

// Expected defines values used for protected claims validation.
// If field has zero value then validation is skipped.
type Expected = jwt.Expected

// Signer represents a signer which takes a payload and produces a signed JWS object.
type Signer = jose.Signer

// SigningKey represents an algorithm/key used to sign a message.
type SigningKey = jose.SigningKey

// SignerOptions represents options that can be set when creating signers.
type SignerOptions = jose.SignerOptions

// Header represents the read-only JOSE header for JWE/JWS objects.
type Header = jose.Header

// HeaderKey represents the type used as a key in the protected header of a JWS
// object.
type HeaderKey = jose.HeaderKey

// ErrInvalidIssuer indicates invalid iss claim.
var ErrInvalidIssuer = jwt.ErrInvalidIssuer

// ErrInvalidAudience indicated invalid aud claim.
var ErrInvalidAudience = jwt.ErrInvalidAudience

// ErrNotValidYet indicates that token is used before time indicated in nbf claim.
var ErrNotValidYet = jwt.ErrNotValidYet

// ErrExpired indicates that token is used after expiry time indicated in exp claim.
var ErrExpired = jwt.ErrExpired

// ErrInvalidSubject indicates invalid sub claim.
var ErrInvalidSubject = jwt.ErrInvalidSubject

// ErrInvalidID indicates invalid jti claim.
var ErrInvalidID = jwt.ErrInvalidID

// Key management algorithms
const (
	RSA1_5             = KeyAlgorithm("RSA1_5")             // RSA-PKCS1v1.5
	RSA_OAEP           = KeyAlgorithm("RSA-OAEP")           // RSA-OAEP-SHA1
	RSA_OAEP_256       = KeyAlgorithm("RSA-OAEP-256")       // RSA-OAEP-SHA256
	A128KW             = KeyAlgorithm("A128KW")             // AES key wrap (128)
	A192KW             = KeyAlgorithm("A192KW")             // AES key wrap (192)
	A256KW             = KeyAlgorithm("A256KW")             // AES key wrap (256)
	DIRECT             = KeyAlgorithm("dir")                // Direct encryption
	ECDH_ES            = KeyAlgorithm("ECDH-ES")            // ECDH-ES
	ECDH_ES_A128KW     = KeyAlgorithm("ECDH-ES+A128KW")     // ECDH-ES + AES key wrap (128)
	ECDH_ES_A192KW     = KeyAlgorithm("ECDH-ES+A192KW")     // ECDH-ES + AES key wrap (192)
	ECDH_ES_A256KW     = KeyAlgorithm("ECDH-ES+A256KW")     // ECDH-ES + AES key wrap (256)
	A128GCMKW          = KeyAlgorithm("A128GCMKW")          // AES-GCM key wrap (128)
	A192GCMKW          = KeyAlgorithm("A192GCMKW")          // AES-GCM key wrap (192)
	A256GCMKW          = KeyAlgorithm("A256GCMKW")          // AES-GCM key wrap (256)
	PBES2_HS256_A128KW = KeyAlgorithm("PBES2-HS256+A128KW") // PBES2 + HMAC-SHA256 + AES key wrap (128)
	PBES2_HS384_A192KW = KeyAlgorithm("PBES2-HS384+A192KW") // PBES2 + HMAC-SHA384 + AES key wrap (192)
	PBES2_HS512_A256KW = KeyAlgorithm("PBES2-HS512+A256KW") // PBES2 + HMAC-SHA512 + AES key wrap (256)
)

// Signature algorithms
const (
	HS256 = "HS256" // HMAC using SHA-256
	HS384 = "HS384" // HMAC using SHA-384
	HS512 = "HS512" // HMAC using SHA-512
	RS256 = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384 = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512 = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256 = "ES256" // ECDSA using P-256 and SHA-256
	ES384 = "ES384" // ECDSA using P-384 and SHA-384
	ES512 = "ES512" // ECDSA using P-521 and SHA-512
	PS256 = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384 = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512 = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
	EdDSA = "EdDSA" // Ed25591
)

// Content encryption algorithms
const (
	A128CBC_HS256 = ContentEncryption("A128CBC-HS256") // AES-CBC + HMAC-SHA256 (128)
	A192CBC_HS384 = ContentEncryption("A192CBC-HS384") // AES-CBC + HMAC-SHA384 (192)
	A256CBC_HS512 = ContentEncryption("A256CBC-HS512") // AES-CBC + HMAC-SHA512 (256)
	A128GCM       = ContentEncryption("A128GCM")       // AES-GCM (128)
	A192GCM       = ContentEncryption("A192GCM")       // AES-GCM (192)
	A256GCM       = ContentEncryption("A256GCM")       // AES-GCM (256)
)

// Elliptic curves
const (
	P256 = "P-256" // P-256 curve (FIPS 186-3)
	P384 = "P-384" // P-384 curve (FIPS 186-3)
	P521 = "P-521" // P-521 curve (FIPS 186-3)
)

// Key types
const (
	EC  = "EC"  // Elliptic curves
	RSA = "RSA" // RSA
	OKP = "OKP" // Ed25519
	OCT = "oct" // Octet sequence
)

// Ed25519 is the EdDSA signature scheme using SHA-512/256 and Curve25519
const Ed25519 = "Ed25519"

// Default key management, signature, and content encryption algorithms to use if none is specified.
const (
	// Key management algorithms
	DefaultECKeyAlgorithm  = ECDH_ES
	DefaultRSAKeyAlgorithm = RSA_OAEP_256
	DefaultOctKeyAlgorithm = A256GCMKW
	// Signature algorithms
	DefaultRSASigAlgorithm  = RS256
	DefaultOctSigsAlgorithm = HS256
	// Content encryption algorithm
	DefaultEncAlgorithm = A256GCM
)

// Default sizes
const (
	DefaultRSASize = 2048
	DefaultOctSize = 32
)

// ParseEncrypted parses an encrypted message in compact or full serialization format.
func ParseEncrypted(input string) (*JSONWebEncryption, error) {
	return jose.ParseEncrypted(input)
}

// NewEncrypter creates an appropriate encrypter based on the key type.
func NewEncrypter(enc ContentEncryption, rcpt Recipient, opts *EncrypterOptions) (Encrypter, error) {
	return jose.NewEncrypter(enc, rcpt, opts)
}

// NewNumericDate constructs NumericDate from time.Time value.
func NewNumericDate(t time.Time) *NumericDate {
	return jwt.NewNumericDate(t)
}

// UnixNumericDate returns a NumericDate from the given seconds since the UNIX
// Epoch time. For backward compatibility is s is 0, a nil value will be returned.
func UnixNumericDate(s int64) *NumericDate {
	if s == 0 {
		return nil
	}
	out := NumericDate(s)
	return &out
}

// NewSigner creates an appropriate signer based on the key type
func NewSigner(sig SigningKey, opts *SignerOptions) (Signer, error) {
	return jose.NewSigner(sig, opts)
}

// ParseSigned parses token from JWS form.
func ParseSigned(s string) (*JSONWebToken, error) {
	return jwt.ParseSigned(s)
}

// Signed creates builder for signed tokens.
func Signed(sig Signer) Builder {
	return jwt.Signed(sig)
}

// ParseJWS parses a signed message in compact or full serialization format.
func ParseJWS(s string) (*JSONWebSignature, error) {
	return jose.ParseSigned(s)
}

// Determine whether a JSONWebKey is symmetric
func IsSymmetric(k *JSONWebKey) bool {
	switch k.Key.(type) {
	case []byte:
		return true
	default:
		return false
	}
}

// Determine whether a JSONWebKey is asymmetric
func IsAsymmetric(k *JSONWebKey) bool {
	return !IsSymmetric(k)
}

// TrimPrefix removes the string "square/go-jose" from all errors.
func TrimPrefix(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(strings.TrimPrefix(err.Error(), "square/go-jose: "))
}
