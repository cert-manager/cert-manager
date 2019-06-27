package provisioner

import "crypto/x509"

// noop provisioners is a provisioner that accepts anything.
type noop struct{}

func (p *noop) GetID() string {
	return "noop"
}

func (p *noop) GetTokenID(token string) (string, error) {
	return "", nil
}

func (p *noop) GetName() string {
	return "noop"
}
func (p *noop) GetType() Type {
	return noopType
}

func (p *noop) GetEncryptedKey() (kid string, key string, ok bool) {
	return "", "", false
}

func (p *noop) Init(config Config) error {
	return nil
}

func (p *noop) AuthorizeSign(token string) ([]SignOption, error) {
	return []SignOption{}, nil
}

func (p *noop) AuthorizeRenewal(cert *x509.Certificate) error {
	return nil
}

func (p *noop) AuthorizeRevoke(token string) error {
	return nil
}
