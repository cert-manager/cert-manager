package keys

import (
	"github.com/pkg/errors"
)

// GenerateDefaultKeyPair generates a public/private key pair using configured
// default values for key type, curve, and size.
func GenerateDefaultKeyPair() (interface{}, interface{}, error) {
	return GenerateKeyPair(DefaultKeyType, DefaultKeyCurve, DefaultKeySize)
}

// GenerateKeyPair creates an asymmetric crypto keypair using input configuration.
func GenerateKeyPair(kty, crv string, size int) (interface{}, interface{}, error) {
	priv, err := GenerateKey(kty, crv, size)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	pub, err := PublicKey(priv)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	return pub, priv, err
}
