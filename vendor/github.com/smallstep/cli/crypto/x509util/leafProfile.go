package x509util

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/pkg/errors"
)

// Leaf implements the Profile for a leaf certificate.
type Leaf struct {
	base
}

// NewLeafProfileWithTemplate returns a new leaf x509 Certificate Profile with
// Subject Certificate set to the value of the template argument.
// A public/private keypair **WILL NOT** be generated for this profile because
// the public key will be populated from the Subject Certificate parameter.
func NewLeafProfileWithTemplate(sub *x509.Certificate, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	withOps = append(withOps, WithPublicKey(sub.PublicKey))
	return newProfile(&Leaf{}, sub, iss, issPriv, withOps...)
}

// NewLeafProfile returns a new leaf x509 Certificate profile.
// A new public/private key pair will be generated for the Profile if
// not set in the `withOps` profile modifiers.
func NewLeafProfile(cn string, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	sub := defaultLeafTemplate(pkix.Name{CommonName: cn}, iss.Subject)
	return newProfile(&Leaf{}, sub, iss, issPriv, withOps...)
}

// NewLeafProfileWithCSR returns a new leaf x509 Certificate Profile with
// Subject Certificate fields populated directly from the CSR.
// A public/private keypair **WILL NOT** be generated for this profile because
// the public key will be populated from the CSR.
func NewLeafProfileWithCSR(csr *x509.CertificateRequest, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	if csr.PublicKey == nil {
		return nil, errors.Errorf("CSR must have PublicKey")
	}

	sub := defaultLeafTemplate(csr.Subject, iss.Subject)
	sub.Extensions = csr.Extensions
	sub.ExtraExtensions = csr.ExtraExtensions
	sub.DNSNames = csr.DNSNames
	sub.EmailAddresses = csr.EmailAddresses
	sub.IPAddresses = csr.IPAddresses
	sub.URIs = csr.URIs

	withOps = append(withOps, WithPublicKey(csr.PublicKey))
	return newProfile(&Leaf{}, sub, iss, issPriv, withOps...)
}

func defaultLeafTemplate(sub pkix.Name, iss pkix.Name) *x509.Certificate {
	notBefore := time.Now()
	return &x509.Certificate{
		IsCA:      false,
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(DefaultCertValidity),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: false,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
		Issuer:                iss,
		Subject:               sub,
	}
}
