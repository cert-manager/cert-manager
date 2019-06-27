package token

import (
	"crypto"
	"encoding/base64"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/jose"
)

const (
	// DefaultIssuer when generating tokens.
	DefaultIssuer = "step-cli"
	// DefaultAudience when generating tokens.
	DefaultAudience = "https://ca/sign"
	// MinValidity token validity token duration.
	MinValidity = 10 * time.Second
	// MaxValidity token validity token duration.
	MaxValidity = 1 * time.Hour
	// DefaultValidity token validity duration.
	DefaultValidity = 5 * time.Minute
	// MaxValidityDelay allowable delay between Now and beginning of token validity period.
	MaxValidityDelay = 30 * time.Minute
)

// RootSHAClaim is the property name for a JWT claim that stores the SHA256 of a root certificate.
const RootSHAClaim = "sha"

// SANSClaim is the property name for a JWT claim that stores the list of required subject alternative names.
const SANSClaim = "sans"

// Token interface which all token types should attempt to implement.
type Token interface {
	SignedString(sigAlg string, priv interface{}) (string, error)
}

// Claims represents the claims that a token might have.
type Claims struct {
	jose.Claims
	ExtraClaims  map[string]interface{}
	ExtraHeaders map[string]interface{}
}

// Set adds the given key and value to the map of extra claims.
func (c *Claims) Set(key string, value interface{}) {
	if c.ExtraClaims == nil {
		c.ExtraClaims = make(map[string]interface{})
	}
	c.ExtraClaims[key] = value
}

// SetHeader adds the given key and value to the map of extra headers.
func (c *Claims) SetHeader(key string, value interface{}) {
	if c.ExtraHeaders == nil {
		c.ExtraHeaders = make(map[string]interface{})
	}
	c.ExtraHeaders[key] = value
}

// Sign creates a JWT with the claims and signs it with the given key.
func (c *Claims) Sign(alg jose.SignatureAlgorithm, key interface{}) (string, error) {
	kid, err := GenerateKeyID(key)
	if err != nil {
		return "", err
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("kid", kid)

	// Used to override the kid too
	for k, v := range c.ExtraHeaders {
		so.WithHeader(jose.HeaderKey(k), v)
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}, so)
	if err != nil {
		return "", errors.Wrapf(err, "error creating JWT signer")
	}

	// Force aud to be a string
	if len(c.Audience) == 1 {
		c.Set("aud", c.Audience[0])
	}

	raw, err := jose.Signed(signer).Claims(c.Claims).Claims(c.ExtraClaims).CompactSerialize()
	if err != nil {
		return "", errors.Wrapf(err, "error serializing JWT")
	}
	return raw, nil
}

// NewClaims returns the default claims with the given options added.
func NewClaims(opts ...Options) (*Claims, error) {
	c := DefaultClaims()
	for _, fn := range opts {
		if err := fn(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// DefaultClaims returns the default claims of any token.
func DefaultClaims() *Claims {
	now := time.Now().UTC()
	return &Claims{
		Claims: jose.Claims{
			Issuer:    DefaultIssuer,
			Audience:  jose.Audience{DefaultAudience},
			Expiry:    jose.NewNumericDate(now.Add(DefaultValidity)),
			NotBefore: jose.NewNumericDate(now),
			IssuedAt:  jose.NewNumericDate(now),
		},
		ExtraClaims: make(map[string]interface{}),
	}
}

// GenerateKeyID returns the SHA256 of a public key.
func GenerateKeyID(priv interface{}) (string, error) {
	pub, err := keys.PublicKey(priv)
	if err != nil {
		return "", errors.Wrap(err, "error generating kid")
	}
	jwk := jose.JSONWebKey{Key: pub}
	keyID, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.Wrap(err, "error generating kid")
	}
	return base64.RawURLEncoding.EncodeToString(keyID), nil
}
