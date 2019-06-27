package x509util

import (
	"crypto/x509"

	"github.com/pkg/errors"
	stepx509 "github.com/smallstep/cli/pkg/x509"
)

// ParseCertificate parses a single certificate from the given ASN.1 DER data.
func ParseCertificate(asn1Data []byte) (*x509.Certificate, error) {
	cert, err := stepx509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate")
	}
	return ToX509Certificate(cert), nil
}

// ParseCertificateRequest parses a single certificate request from the given
// ASN.1 DER data.
func ParseCertificateRequest(asn1Data []byte) (*x509.CertificateRequest, error) {
	csr, err := stepx509.ParseCertificateRequest(asn1Data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate request")
	}
	return ToX509CertificateRequest(csr), nil
}

// CheckCertificateRequestSignature verifies that signature is a valid signature
// over signed from csr's public key.
//
// CheckCertificateRequestSignature reports whether the signature on csr is
// valid.
func CheckCertificateRequestSignature(csr *x509.CertificateRequest) error {
	if stepx509.SignatureAlgorithm(csr.SignatureAlgorithm) == stepx509.ED25519SIG {
		return ToStepX509CertificateRequest(csr).CheckSignature()
	}
	return csr.CheckSignature()
}

// ToStepX509Certificate converts a x509.Certificate from the standard library
// to the step version of the x509.Certificate.
func ToStepX509Certificate(cert *x509.Certificate) *stepx509.Certificate {
	return &stepx509.Certificate{
		Raw:                         cert.Raw,
		RawTBSCertificate:           cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     cert.RawSubjectPublicKeyInfo,
		RawSubject:                  cert.RawSubject,
		RawIssuer:                   cert.RawIssuer,
		Signature:                   cert.Signature,
		SignatureAlgorithm:          stepx509.SignatureAlgorithm(cert.SignatureAlgorithm),
		PublicKeyAlgorithm:          stepx509.PublicKeyAlgorithm(cert.PublicKeyAlgorithm),
		PublicKey:                   cert.PublicKey,
		Version:                     cert.Version,
		SerialNumber:                cert.SerialNumber,
		Issuer:                      cert.Issuer,
		Subject:                     cert.Subject,
		NotBefore:                   cert.NotBefore,
		NotAfter:                    cert.NotAfter,
		KeyUsage:                    stepx509.KeyUsage(cert.KeyUsage),
		Extensions:                  cert.Extensions,
		ExtraExtensions:             cert.ExtraExtensions,
		UnhandledCriticalExtensions: cert.UnhandledCriticalExtensions,
		ExtKeyUsage:                 toStepExtKeyUsage(cert.ExtKeyUsage),
		UnknownExtKeyUsage:          cert.UnknownExtKeyUsage,
		BasicConstraintsValid:       cert.BasicConstraintsValid,
		IsCA:                        cert.IsCA,
		MaxPathLen:                  cert.MaxPathLen,
		MaxPathLenZero:              cert.MaxPathLenZero,
		SubjectKeyId:                cert.SubjectKeyId,
		AuthorityKeyId:              cert.AuthorityKeyId,
		OCSPServer:                  cert.OCSPServer,
		IssuingCertificateURL:       cert.IssuingCertificateURL,
		DNSNames:                    cert.DNSNames,
		EmailAddresses:              cert.EmailAddresses,
		IPAddresses:                 cert.IPAddresses,
		URIs:                        cert.URIs,
		PermittedDNSDomainsCritical: cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         cert.PermittedDNSDomains,
		ExcludedDNSDomains:          cert.ExcludedDNSDomains,
		PermittedIPRanges:           cert.PermittedIPRanges,
		ExcludedIPRanges:            cert.ExcludedIPRanges,
		PermittedEmailAddresses:     cert.PermittedEmailAddresses,
		ExcludedEmailAddresses:      cert.ExcludedEmailAddresses,
		PermittedURIDomains:         cert.PermittedURIDomains,
		ExcludedURIDomains:          cert.ExcludedURIDomains,
		CRLDistributionPoints:       cert.CRLDistributionPoints,
		PolicyIdentifiers:           cert.PolicyIdentifiers,
	}
}

func toStepExtKeyUsage(eku []x509.ExtKeyUsage) []stepx509.ExtKeyUsage {
	var ret []stepx509.ExtKeyUsage
	for _, u := range eku {
		ret = append(ret, stepx509.ExtKeyUsage(u))
	}
	return ret
}

// ToX509Certificate converts a x509.Certificate from the internal package to
// the standard version of the x509.Certificate.
func ToX509Certificate(cert *stepx509.Certificate) *x509.Certificate {
	return &x509.Certificate{
		Raw:                         cert.Raw,
		RawTBSCertificate:           cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     cert.RawSubjectPublicKeyInfo,
		RawSubject:                  cert.RawSubject,
		RawIssuer:                   cert.RawIssuer,
		Signature:                   cert.Signature,
		SignatureAlgorithm:          x509.SignatureAlgorithm(cert.SignatureAlgorithm),
		PublicKeyAlgorithm:          x509.PublicKeyAlgorithm(cert.PublicKeyAlgorithm),
		PublicKey:                   cert.PublicKey,
		Version:                     cert.Version,
		SerialNumber:                cert.SerialNumber,
		Issuer:                      cert.Issuer,
		Subject:                     cert.Subject,
		NotBefore:                   cert.NotBefore,
		NotAfter:                    cert.NotAfter,
		KeyUsage:                    x509.KeyUsage(cert.KeyUsage),
		Extensions:                  cert.Extensions,
		ExtraExtensions:             cert.ExtraExtensions,
		UnhandledCriticalExtensions: cert.UnhandledCriticalExtensions,
		ExtKeyUsage:                 toExtKeyUsage(cert.ExtKeyUsage),
		UnknownExtKeyUsage:          cert.UnknownExtKeyUsage,
		BasicConstraintsValid:       cert.BasicConstraintsValid,
		IsCA:                        cert.IsCA,
		MaxPathLen:                  cert.MaxPathLen,
		MaxPathLenZero:              cert.MaxPathLenZero,
		SubjectKeyId:                cert.SubjectKeyId,
		AuthorityKeyId:              cert.AuthorityKeyId,
		OCSPServer:                  cert.OCSPServer,
		IssuingCertificateURL:       cert.IssuingCertificateURL,
		DNSNames:                    cert.DNSNames,
		EmailAddresses:              cert.EmailAddresses,
		IPAddresses:                 cert.IPAddresses,
		URIs:                        cert.URIs,
		PermittedDNSDomainsCritical: cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         cert.PermittedDNSDomains,
		ExcludedDNSDomains:          cert.ExcludedDNSDomains,
		PermittedIPRanges:           cert.PermittedIPRanges,
		ExcludedIPRanges:            cert.ExcludedIPRanges,
		PermittedEmailAddresses:     cert.PermittedEmailAddresses,
		ExcludedEmailAddresses:      cert.ExcludedEmailAddresses,
		PermittedURIDomains:         cert.PermittedURIDomains,
		ExcludedURIDomains:          cert.ExcludedURIDomains,
		CRLDistributionPoints:       cert.CRLDistributionPoints,
		PolicyIdentifiers:           cert.PolicyIdentifiers,
	}
}

func toExtKeyUsage(eku []stepx509.ExtKeyUsage) []x509.ExtKeyUsage {
	var ret []x509.ExtKeyUsage
	for _, u := range eku {
		ret = append(ret, x509.ExtKeyUsage(u))
	}
	return ret
}

// ToStepX509CertificateRequest converts a x509.CertificateRequest from the standard library
// to the step version of the x509.CertificateRequest.
func ToStepX509CertificateRequest(csr *x509.CertificateRequest) *stepx509.CertificateRequest {
	return &stepx509.CertificateRequest{
		Raw:                      csr.Raw,
		RawTBSCertificateRequest: csr.RawTBSCertificateRequest,
		RawSubjectPublicKeyInfo:  csr.RawSubjectPublicKeyInfo,
		RawSubject:               csr.RawSubject,
		Version:                  csr.Version,
		Signature:                csr.Signature,
		SignatureAlgorithm:       stepx509.SignatureAlgorithm(csr.SignatureAlgorithm),
		PublicKeyAlgorithm:       stepx509.PublicKeyAlgorithm(csr.PublicKeyAlgorithm),
		PublicKey:                csr.PublicKey,
		Subject:                  csr.Subject,
		Attributes:               csr.Attributes,
		Extensions:               csr.Extensions,
		ExtraExtensions:          csr.ExtraExtensions,
		DNSNames:                 csr.DNSNames,
		EmailAddresses:           csr.EmailAddresses,
		IPAddresses:              csr.IPAddresses,
		URIs:                     csr.URIs,
	}
}

// ToX509CertificateRequest converts a x509.CertificateRequest from the internal package to
// the standard version of the x509.CertificateRequest.
func ToX509CertificateRequest(csr *stepx509.CertificateRequest) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Raw:                      csr.Raw,
		RawTBSCertificateRequest: csr.RawTBSCertificateRequest,
		RawSubjectPublicKeyInfo:  csr.RawSubjectPublicKeyInfo,
		RawSubject:               csr.RawSubject,
		Version:                  csr.Version,
		Signature:                csr.Signature,
		SignatureAlgorithm:       x509.SignatureAlgorithm(csr.SignatureAlgorithm),
		PublicKeyAlgorithm:       x509.PublicKeyAlgorithm(csr.PublicKeyAlgorithm),
		PublicKey:                csr.PublicKey,
		Subject:                  csr.Subject,
		Attributes:               csr.Attributes,
		Extensions:               csr.Extensions,
		ExtraExtensions:          csr.ExtraExtensions,
		DNSNames:                 csr.DNSNames,
		EmailAddresses:           csr.EmailAddresses,
		IPAddresses:              csr.IPAddresses,
		URIs:                     csr.URIs,
	}
}
