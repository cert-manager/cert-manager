/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

func IPAddressesForCertificate(crt *v1.Certificate) []net.IP {
	var ipAddresses []net.IP
	var ip net.IP
	for _, ipName := range crt.Spec.IPAddresses {
		ip = net.ParseIP(ipName)
		if ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}
	return ipAddresses
}

func URIsForCertificate(crt *v1.Certificate) ([]*url.URL, error) {
	uris, err := URLsFromStrings(crt.Spec.URIs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URIs: %s", err)
	}

	return uris, nil
}

func DNSNamesForCertificate(crt *v1.Certificate) ([]string, error) {
	_, err := URLsFromStrings(crt.Spec.DNSNames)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNSNames: %s", err)
	}

	return crt.Spec.DNSNames, nil
}

func URLsFromStrings(urlStrs []string) ([]*url.URL, error) {
	var urls []*url.URL
	var errs []string

	for _, urlStr := range urlStrs {
		url, err := url.Parse(urlStr)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}

		urls = append(urls, url)
	}

	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, ", "))
	}

	return urls, nil
}

func IPAddressesToString(ipAddresses []net.IP) []string {
	var ipNames []string
	for _, ip := range ipAddresses {
		ipNames = append(ipNames, ip.String())
	}
	return ipNames
}

func URLsToString(uris []*url.URL) []string {
	var uriStrs []string
	for _, uri := range uris {
		if uri == nil {
			panic("provided uri to string is nil")
		}

		uriStrs = append(uriStrs, uri.String())
	}

	return uriStrs
}

func removeDuplicates(in []string) []string {
	var found []string
Outer:
	for _, i := range in {
		for _, i2 := range found {
			if i2 == i {
				continue Outer
			}
		}
		found = append(found, i)
	}
	return found
}

// OrganizationForCertificate will return the Organization to set for the
// Certificate resource.
// If an Organization is not specifically set, a default will be used.
func OrganizationForCertificate(crt *v1.Certificate) []string {
	if crt.Spec.Subject == nil {
		return nil
	}
	return crt.Spec.Subject.Organizations
}

// SubjectForCertificate will return the Subject from the Certificate resource or an empty one if it is not set
func SubjectForCertificate(crt *v1.Certificate) v1.X509Subject {
	if crt.Spec.Subject == nil {
		return v1.X509Subject{}
	}

	return *crt.Spec.Subject
}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func BuildKeyUsages(usages []v1.KeyUsage, isCA bool) (ku x509.KeyUsage, eku []x509.ExtKeyUsage, err error) {
	var unk []v1.KeyUsage
	if isCA {
		ku |= x509.KeyUsageCertSign
	}
	if len(usages) == 0 {
		usages = append(usages, v1.DefaultKeyUsages()...)
	}
	for _, u := range usages {
		if kuse, ok := apiutil.KeyUsageType(u); ok {
			ku |= kuse
		} else if ekuse, ok := apiutil.ExtKeyUsageType(u); ok {
			eku = append(eku, ekuse)
		} else {
			unk = append(unk, u)
		}
	}
	if len(unk) > 0 {
		err = fmt.Errorf("unknown key usages: %v", unk)
	}
	return
}

func BuildCertManagerKeyUsages(ku x509.KeyUsage, eku []x509.ExtKeyUsage) []v1.KeyUsage {
	usages := apiutil.KeyUsageStrings(ku)
	usages = append(usages, apiutil.ExtKeyUsageStrings(eku)...)

	return usages
}

// GenerateCSR will generate a new *x509.CertificateRequest template to be used
// by issuers that utilise CSRs to obtain Certificates.
// The CSR will not be signed, and should be passed to either EncodeCSR or
// to the x509.CreateCertificateRequest function.
func GenerateCSR(crt *v1.Certificate) (*x509.CertificateRequest, error) {
	commonName := crt.Spec.CommonName
	iPAddresses := IPAddressesForCertificate(crt)
	organization := OrganizationForCertificate(crt)
	subject := SubjectForCertificate(crt)

	dnsNames, err := DNSNamesForCertificate(crt)
	if err != nil {
		return nil, err
	}

	uriNames, err := URIsForCertificate(crt)
	if err != nil {
		return nil, err
	}

	if len(commonName) == 0 && len(dnsNames) == 0 && len(uriNames) == 0 && len(crt.Spec.EmailAddresses) == 0 && len(crt.Spec.IPAddresses) == 0 {
		return nil, fmt.Errorf("no common name, DNS name, URI SAN, or Email SAN specified on certificate")
	}

	pubKeyAlgo, sigAlgo, err := SignatureAlgorithm(crt)
	if err != nil {
		return nil, err
	}

	var extraExtensions []pkix.Extension
	if crt.Spec.EncodeUsagesInRequest == nil || *crt.Spec.EncodeUsagesInRequest {
		extraExtensions, err = buildKeyUsagesExtensionsForCertificate(crt)
		if err != nil {
			return nil, err
		}
	}

	return &x509.CertificateRequest{
		Version:            3,
		SignatureAlgorithm: sigAlgo,
		PublicKeyAlgorithm: pubKeyAlgo,
		Subject: pkix.Name{
			Country:            subject.Countries,
			Organization:       organization,
			OrganizationalUnit: subject.OrganizationalUnits,
			Locality:           subject.Localities,
			Province:           subject.Provinces,
			StreetAddress:      subject.StreetAddresses,
			PostalCode:         subject.PostalCodes,
			SerialNumber:       subject.SerialNumber,
			CommonName:         commonName,
		},
		DNSNames:        dnsNames,
		IPAddresses:     iPAddresses,
		URIs:            uriNames,
		EmailAddresses:  crt.Spec.EmailAddresses,
		ExtraExtensions: extraExtensions,
	}, nil
}

func buildKeyUsagesExtensionsForCertificate(crt *v1.Certificate) ([]pkix.Extension, error) {
	ku, ekus, err := BuildKeyUsages(crt.Spec.Usages, crt.Spec.IsCA)
	if err != nil {
		return nil, fmt.Errorf("failed to build key usages: %w", err)
	}

	usage, err := buildASN1KeyUsageRequest(ku)
	if err != nil {
		return nil, fmt.Errorf("failed to asn1 encode usages: %w", err)
	}
	asn1ExtendedUsages := []asn1.ObjectIdentifier{}
	for _, eku := range ekus {
		if oid, ok := OIDFromExtKeyUsage(eku); ok {
			asn1ExtendedUsages = append(asn1ExtendedUsages, oid)
		}
	}

	extraExtensions := []pkix.Extension{usage}
	if len(ekus) > 0 {
		extendedUsage := pkix.Extension{
			Id: OIDExtensionExtendedKeyUsage,
		}
		extendedUsage.Value, err = asn1.Marshal(asn1ExtendedUsages)
		if err != nil {
			return nil, fmt.Errorf("failed to asn1 encode extended usages: %w", err)
		}

		extraExtensions = append(extraExtensions, extendedUsage)
	}
	return extraExtensions, nil
}

// GenerateTemplate will create a x509.Certificate for the given Certificate resource.
// This should create a Certificate template that is equivalent to the CertificateRequest
// generated by GenerateCSR.
// The PublicKey field must be populated by the caller.
func GenerateTemplate(crt *v1.Certificate) (*x509.Certificate, error) {
	commonName := crt.Spec.CommonName
	dnsNames := crt.Spec.DNSNames
	ipAddresses := IPAddressesForCertificate(crt)
	organization := OrganizationForCertificate(crt)
	subject := SubjectForCertificate(crt)
	uris, err := URLsFromStrings(crt.Spec.URIs)
	if err != nil {
		return nil, err
	}
	keyUsages, extKeyUsages, err := BuildKeyUsages(crt.Spec.Usages, crt.Spec.IsCA)
	if err != nil {
		return nil, err
	}

	if len(commonName) == 0 && len(dnsNames) == 0 && len(ipAddresses) == 0 && len(uris) == 0 && len(crt.Spec.EmailAddresses) == 0 {
		return nil, fmt.Errorf("no common name or subject alt names requested on certificate")
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err.Error())
	}

	certDuration := apiutil.DefaultCertDuration(crt.Spec.Duration)

	pubKeyAlgo, _, err := SignatureAlgorithm(crt)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    pubKeyAlgo,
		IsCA:                  crt.Spec.IsCA,
		Subject: pkix.Name{
			Country:            subject.Countries,
			Organization:       organization,
			OrganizationalUnit: subject.OrganizationalUnits,
			Locality:           subject.Localities,
			Province:           subject.Provinces,
			StreetAddress:      subject.StreetAddresses,
			PostalCode:         subject.PostalCodes,
			SerialNumber:       subject.SerialNumber,
			CommonName:         commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(certDuration),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage:       keyUsages,
		ExtKeyUsage:    extKeyUsages,
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		URIs:           uris,
		EmailAddresses: crt.Spec.EmailAddresses,
	}, nil
}

// GenerateTemplate will create a x509.Certificate for the given
// CertificateRequest resource
func GenerateTemplateFromCertificateRequest(cr *v1.CertificateRequest) (*x509.Certificate, error) {
	certDuration := apiutil.DefaultCertDuration(cr.Spec.Duration)
	keyUsage, extKeyUsage, err := BuildKeyUsages(cr.Spec.Usages, cr.Spec.IsCA)
	if err != nil {
		return nil, err
	}
	return GenerateTemplateFromCSRPEMWithUsages(cr.Spec.Request, certDuration, cr.Spec.IsCA, keyUsage, extKeyUsage)
}

func GenerateTemplateFromCSRPEM(csrPEM []byte, duration time.Duration, isCA bool) (*x509.Certificate, error) {
	var (
		ku  x509.KeyUsage
		eku []x509.ExtKeyUsage
	)
	return GenerateTemplateFromCSRPEMWithUsages(csrPEM, duration, isCA, ku, eku)
}

func GenerateTemplateFromCSRPEMWithUsages(csrPEM []byte, duration time.Duration, isCA bool, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) (*x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("failed to decode csr")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err.Error())
	}

	return &x509.Certificate{
		Version:               csr.Version,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		IsCA:                  isCA,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage:       keyUsage,
		ExtKeyUsage:    extKeyUsage,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}, nil
}

// SignCertificate returns a signed *x509.Certificate given a template
// *x509.Certificate crt and an issuer.
// publicKey is the public key of the signee, and signerKey is the private
// key of the signer.
// It returns a PEM encoded copy of the Certificate as well as a *x509.Certificate
// which can be used for reading the encoded values.
func SignCertificate(template *x509.Certificate, issuerCert *x509.Certificate, publicKey crypto.PublicKey, signerKey interface{}) ([]byte, *x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, signerKey)

	if err != nil {
		return nil, nil, fmt.Errorf("error creating x509 certificate: %s", err.Error())
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding DER certificate bytes: %s", err.Error())
	}

	pemBytes := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding certificate PEM: %s", err.Error())
	}

	return pemBytes.Bytes(), cert, err
}

// SignCSRTemplate signs a certificate template usually based upon a CSR. This
// function expects all fields to be present in the certificate template,
// including it's public key.
// It returns the PEM bundle containing certificate data and the CA data, encoded in PEM format.
func SignCSRTemplate(caCerts []*x509.Certificate, caKey crypto.Signer, template *x509.Certificate) (PEMBundle, error) {
	if len(caCerts) == 0 {
		return PEMBundle{}, errors.New("no CA certificates given to sign CSR template")
	}

	issuingCACert := caCerts[0]

	_, cert, err := SignCertificate(template, issuingCACert, template.PublicKey, caKey)
	if err != nil {
		return PEMBundle{}, err
	}

	bundle, err := ParseSingleCertificateChain(append(caCerts, cert))
	if err != nil {
		return PEMBundle{}, err
	}

	return bundle, nil
}

// EncodeCSR calls x509.CreateCertificateRequest to sign the given CSR template.
// It returns a DER encoded signed CSR.
func EncodeCSR(template *x509.CertificateRequest, key crypto.Signer) ([]byte, error) {
	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("error creating x509 certificate: %s", err.Error())
	}

	return derBytes, nil
}

// EncodeX509 will encode a single *x509.Certificate into PEM format.
func EncodeX509(cert *x509.Certificate) ([]byte, error) {
	caPem := bytes.NewBuffer([]byte{})
	err := pem.Encode(caPem, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return nil, err
	}

	return caPem.Bytes(), nil
}

// EncodeX509Chain will encode a list of *x509.Certificates into a PEM format chain.
// Self-signed certificates are not included as per
// https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2
// Certificates are output in the order they're given; if the input is not ordered
// as specified in RFC5246 section 7.4.2, the resulting chain might not be valid
// for use in TLS.
func EncodeX509Chain(certs []*x509.Certificate) ([]byte, error) {
	caPem := bytes.NewBuffer([]byte{})
	for _, cert := range certs {
		if cert == nil {
			continue
		}

		if cert.CheckSignatureFrom(cert) == nil {
			// Don't include self-signed certificate
			continue
		}

		err := pem.Encode(caPem, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			return nil, err
		}
	}

	return caPem.Bytes(), nil
}

// SignatureAlgorithm will determine the appropriate signature algorithm for
// the given certificate.
// Adapted from https://github.com/cloudflare/cfssl/blob/master/csr/csr.go#L102
func SignatureAlgorithm(crt *v1.Certificate) (x509.PublicKeyAlgorithm, x509.SignatureAlgorithm, error) {
	var sigAlgo x509.SignatureAlgorithm
	var pubKeyAlgo x509.PublicKeyAlgorithm
	var specAlgorithm v1.PrivateKeyAlgorithm
	if crt.Spec.PrivateKey != nil {
		specAlgorithm = crt.Spec.PrivateKey.Algorithm
	}
	switch specAlgorithm {
	case v1.PrivateKeyAlgorithm(""):
		// If keyAlgorithm is not specified, we default to rsa with keysize 2048
		pubKeyAlgo = x509.RSA
		sigAlgo = x509.SHA256WithRSA
	case v1.RSAKeyAlgorithm:
		pubKeyAlgo = x509.RSA
		switch {
		case crt.Spec.PrivateKey.Size >= 4096:
			sigAlgo = x509.SHA512WithRSA
		case crt.Spec.PrivateKey.Size >= 3072:
			sigAlgo = x509.SHA384WithRSA
		case crt.Spec.PrivateKey.Size >= 2048:
			sigAlgo = x509.SHA256WithRSA
		// 0 == not set
		case crt.Spec.PrivateKey.Size == 0:
			sigAlgo = x509.SHA256WithRSA
		default:
			return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported rsa keysize specified: %d. min keysize %d", crt.Spec.PrivateKey.Size, MinRSAKeySize)
		}
	case v1.ECDSAKeyAlgorithm:
		pubKeyAlgo = x509.ECDSA
		switch crt.Spec.PrivateKey.Size {
		case 521:
			sigAlgo = x509.ECDSAWithSHA512
		case 384:
			sigAlgo = x509.ECDSAWithSHA384
		case 256:
			sigAlgo = x509.ECDSAWithSHA256
		case 0:
			sigAlgo = x509.ECDSAWithSHA256
		default:
			return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported ecdsa keysize specified: %d", crt.Spec.PrivateKey.Size)
		}
	default:
		return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported algorithm specified: %s. should be either 'ecdsa' or 'rsa", crt.Spec.PrivateKey.Algorithm)
	}
	return pubKeyAlgo, sigAlgo, nil
}
