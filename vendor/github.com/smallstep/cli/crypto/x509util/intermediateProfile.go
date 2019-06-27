package x509util

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// DefaultIntermediateCertValidity is the default validity of a intermediate certificate in the step PKI.
var DefaultIntermediateCertValidity = time.Hour * 24 * 365 * 10

// Intermediate implements the Profile for a intermediate certificate.
type Intermediate struct {
	base
}

// DefaultDuration returns the default Intermediate Certificate duration.
func (i *Intermediate) DefaultDuration() time.Duration {
	return DefaultIntermediateCertValidity
}

// NewIntermediateProfile returns a new intermediate x509 Certificate profile.
func NewIntermediateProfile(name string, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	sub := defaultIntermediateTemplate(name)
	return newProfile(&Intermediate{}, sub, iss, issPriv, withOps...)
}

func defaultIntermediateTemplate(name string) *x509.Certificate {
	notBefore := time.Now()
	return &x509.Certificate{
		IsCA:                  true,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(DefaultIntermediateCertValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		Issuer:                pkix.Name{CommonName: name},
		Subject:               pkix.Name{CommonName: name},
	}
}
