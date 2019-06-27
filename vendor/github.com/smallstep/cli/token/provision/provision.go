package provision

import (
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
)

// Token defines a one time use token that is intended to be exchanged
// for a newly provisioned certificate by an end entity. Token differs
// from BootstrapToken because it does not self contain networking information
// for connecting to the certificate authority or gatewayconsole.
//
// Token implements the Token interface.
type Token struct {
	claims *token.Claims
}

// New returns a new unsigned One-Time-Token for authorizing a
// single request from a newly provisioned end-entity.
// The current implementation uses jwt.Token and is generated using sane defaults
// for the claims.
// See token/options.go for default claim definitions.
func New(subject string, opts ...token.Options) (*Token, error) {
	o := append([]token.Options{token.WithSubject(subject)}, opts...)
	c, err := token.NewClaims(o...)
	if err != nil {
		return nil, err
	}
	return &Token{claims: c}, nil
}

// SignedString implementation of the Token interface. It returns a JWT using
// the compact serialization.
func (t *Token) SignedString(sigAlg string, key interface{}) (string, error) {
	return t.claims.Sign(jose.SignatureAlgorithm(sigAlg), key)
}
