package token

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/jose"
)

// Options is a function that set claims.
type Options func(c *Claims) error

// WithClaim is an Options function that adds a custom claim to the JWT.
func WithClaim(name string, value interface{}) Options {
	return func(c *Claims) error {
		if name == "" {
			return errors.New("name cannot be empty")
		}
		c.Set(name, value)
		return nil
	}
}

// WithRootCA returns an Options function that calculates the SHA256 of the
// given root certificate to be used in the token claims. If this method it's
// not used the default root certificate in the $STEPPATH secrets directory will
// be used.
func WithRootCA(path string) Options {
	return func(c *Claims) error {
		cert, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(cert.Raw)
		c.Set(RootSHAClaim, hex.EncodeToString(sum[:]))
		return nil
	}
}

// WithSHA returns an Options function that sets the SHA claim to the given
// value.
func WithSHA(sum string) Options {
	return func(c *Claims) error {
		c.Set(RootSHAClaim, sum)
		return nil
	}
}

// WithSANS returns an Options function that sets the list of required SANs
// in the token claims.
func WithSANS(sans []string) Options {
	return func(c *Claims) error {
		c.Set(SANSClaim, sans)
		return nil
	}
}

// WithValidity validates boundary inputs and sets the 'nbf' (NotBefore) and
// 'exp' (expiration) options.
func WithValidity(notBefore, expiration time.Time) Options {
	return func(c *Claims) error {
		now := time.Now().UTC()
		if expiration.Before(notBefore) {
			return errors.Errorf("nbf < exp: nbf=%v, exp=%v", notBefore, expiration)
		}
		requestedDelay := notBefore.Sub(now)
		if requestedDelay > MaxValidityDelay {
			return errors.Errorf("requested validity delay is too long: 'requested validity delay'=%v, 'max validity delay'=%v", requestedDelay, MaxValidityDelay)
		}
		requestedValidity := expiration.Sub(notBefore)
		if requestedValidity < MinValidity {
			return errors.Errorf("requested token validity is too short: 'requested token validity'=%v, 'minimum token validity'=%v", requestedValidity, MinValidity)
		} else if requestedValidity > MaxValidity {
			return errors.Errorf("requested token validity is too long: 'requested token validity'=%v, 'maximum token validity'=%v", requestedValidity, MaxValidity)
		}
		c.NotBefore = jose.NewNumericDate(notBefore)
		c.Expiry = jose.NewNumericDate(expiration)
		return nil
	}
}

// WithIssuer returns an Options function that sets the issuer to use in the
// token claims. If Issuer is not used the default issuer will be used.
func WithIssuer(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("issuer cannot be empty")
		}
		c.Issuer = s
		return nil
	}
}

// WithSubject returns an Options that sets the subject to use in the token
// claims.
func WithSubject(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("subject cannot be empty")
		}
		c.Subject = s
		return nil
	}
}

// WithAudience returns a Options that sets the audience to use in the token
// claims. If Audience is not used the default audience will be used.
func WithAudience(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("audience cannot be empty")
		}
		c.Audience = append(jose.Audience{}, s)
		return nil
	}
}

// WithJWTID returns a Options that sets the jwtID to use in the token
// claims. If WithJWTID is not used a random identifier will be used.
func WithJWTID(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("jwtID cannot be empty")
		}
		c.ID = s
		return nil
	}
}

// WithKid returns a Options that sets the header kid claims.
// If WithKid is not used a thumbprint using SHA256 will be used.
func WithKid(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("kid cannot be empty")
		}
		c.SetHeader("kid", s)
		return nil
	}
}
