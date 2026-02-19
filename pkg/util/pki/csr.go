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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// IPAddressesToString converts a slice of IP addresses to strings, which can be useful for
// printing a list of addresses but MUST NOT be used for comparing two slices of IP addresses.
func IPAddressesToString(ipAddresses []net.IP) []string {
	var ipNames []string
	for _, ip := range ipAddresses {
		ipNames = append(ipNames, ip.String())
	}
	return ipNames
}

func IPAddressesFromStrings(ipStrings []string) ([]net.IP, error) {
	var ipAddresses []net.IP
	for _, ipString := range ipStrings {
		ip, err := netip.ParseAddr(ipString)
		if err != nil || ip.Zone() != "" {
			return nil, err
		}
		addr := ip.AsSlice()
		if len(addr) == 0 {
			return nil, fmt.Errorf("failed to parse IP address %q", ipString)
		}
		ipAddresses = append(ipAddresses, net.IP(addr))
	}
	return ipAddresses, nil
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

// SubjectForCertificate will return the Subject from the Certificate resource or an empty one if it is not set
func SubjectForCertificate(crt *v1.Certificate) v1.X509Subject {
	if crt.Spec.Subject == nil {
		return v1.X509Subject{}
	}

	return *crt.Spec.Subject
}

func KeyUsagesForCertificateOrCertificateRequest(usages []v1.KeyUsage, isCA bool) (ku x509.KeyUsage, eku []x509.ExtKeyUsage, err error) {
	var unk []v1.KeyUsage
	if isCA {
		ku |= x509.KeyUsageCertSign
	}

	// If no usages are specified, default to the ones specified in the
	// Kubernetes API.
	if len(usages) == 0 {
		usages = v1.DefaultKeyUsages()
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

type generateCSROptions struct {
	EncodeBasicConstraintsInRequest bool
	EncodeNameConstraints           bool
	EncodeOtherNames                bool
	UseLiteralSubject               bool
}

type GenerateCSROption func(*generateCSROptions)

// WithEncodeBasicConstraintsInRequest determines whether the BasicConstraints
// extension should be encoded in the CSR.
// NOTE: this is a temporary option that will be removed in a future release.
func WithEncodeBasicConstraintsInRequest(encode bool) GenerateCSROption {
	return func(o *generateCSROptions) {
		o.EncodeBasicConstraintsInRequest = encode
	}
}

func WithNameConstraints(enabled bool) GenerateCSROption {
	return func(o *generateCSROptions) {
		o.EncodeNameConstraints = enabled
	}
}

func WithOtherNames(enabled bool) GenerateCSROption {
	return func(o *generateCSROptions) {
		o.EncodeOtherNames = enabled
	}
}

func WithUseLiteralSubject(useLiteralSubject bool) GenerateCSROption {
	return func(o *generateCSROptions) {
		o.UseLiteralSubject = useLiteralSubject
	}
}

// GenerateCSR will generate a new *x509.CertificateRequest template to be used
// by issuers that utilise CSRs to obtain Certificates.
// The CSR will not be signed, and should be passed to either EncodeCSR or
// to the x509.CreateCertificateRequest function.
func GenerateCSR(crt *v1.Certificate, optFuncs ...GenerateCSROption) (*x509.CertificateRequest, error) {
	opts := &generateCSROptions{
		EncodeBasicConstraintsInRequest: false,
		EncodeNameConstraints:           false,
		EncodeOtherNames:                false,
		UseLiteralSubject:               false,
	}
	for _, opt := range optFuncs {
		opt(opts)
	}

	// Generate the Subject field for the CSR.
	var commonName string
	var rdnSubject pkix.RDNSequence
	if opts.UseLiteralSubject && len(crt.Spec.LiteralSubject) > 0 {
		subjectRDNSequence, err := UnmarshalSubjectStringToRDNSequence(crt.Spec.LiteralSubject)
		if err != nil {
			return nil, err
		}

		commonName = ExtractCommonNameFromRDNSequence(subjectRDNSequence)
		rdnSubject = subjectRDNSequence
	} else {
		subject := SubjectForCertificate(crt)

		commonName = crt.Spec.CommonName
		rdnSubject = pkix.Name{
			Country:            subject.Countries,
			Organization:       subject.Organizations,
			OrganizationalUnit: subject.OrganizationalUnits,
			Locality:           subject.Localities,
			Province:           subject.Provinces,
			StreetAddress:      subject.StreetAddresses,
			PostalCode:         subject.PostalCodes,
			SerialNumber:       subject.SerialNumber,
			CommonName:         commonName,
		}.ToRDNSequence()
	}

	// Generate the SANs for the CSR.
	ipAddresses, err := IPAddressesFromStrings(crt.Spec.IPAddresses)
	if err != nil {
		return nil, err
	}

	sans := GeneralNames{
		RFC822Names:                crt.Spec.EmailAddresses,
		DNSNames:                   crt.Spec.DNSNames,
		UniformResourceIdentifiers: crt.Spec.URIs,
		IPAddresses:                ipAddresses,
	}

	if opts.EncodeOtherNames {
		for _, otherName := range crt.Spec.OtherNames {
			oid, err := ParseObjectIdentifier(otherName.OID)
			if err != nil {
				return nil, err
			}

			value, err := MarshalUniversalValue(UniversalValue{
				UTF8String: otherName.UTF8Value,
			})
			if err != nil {
				return nil, err
			}

			sans.OtherNames = append(sans.OtherNames, OtherName{
				TypeID: oid,
				Value: asn1.RawValue{
					Tag:        0,
					Class:      asn1.ClassContextSpecific,
					IsCompound: true,
					Bytes:      value,
				},
			})
		}
	}

	if len(commonName) == 0 && sans.Empty() {
		return nil, fmt.Errorf("at least one of commonName (from the commonName field or from a literalSubject), dnsNames, emailSANs, ipAddresses, otherNames, or uriSANs must be set")
	}

	pubKeyAlgo, sigAlgo, err := SignatureAlgorithm(crt)
	if err != nil {
		return nil, err
	}

	asn1Subject, err := MarshalRDNSequenceToRawDERBytes(rdnSubject)
	if err != nil {
		return nil, err
	}

	var extraExtensions []pkix.Extension

	if !sans.Empty() {
		sanExtension, err := MarshalSANs(sans, !IsASN1SubjectEmpty(asn1Subject))
		if err != nil {
			return nil, err
		}
		extraExtensions = append(extraExtensions, sanExtension)
	}

	if crt.Spec.EncodeUsagesInRequest == nil || *crt.Spec.EncodeUsagesInRequest {
		ku, ekus, err := KeyUsagesForCertificateOrCertificateRequest(crt.Spec.Usages, crt.Spec.IsCA)
		if err != nil {
			return nil, fmt.Errorf("failed to build key usages: %w", err)
		}

		if ku != 0 {
			usage, err := MarshalKeyUsage(ku)
			if err != nil {
				return nil, fmt.Errorf("failed to asn1 encode usages: %w", err)
			}
			extraExtensions = append(extraExtensions, usage)
		}

		// Only add extended usages if they are specified.
		if len(ekus) > 0 {
			extendedUsages, err := MarshalExtKeyUsage(ekus, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to asn1 encode extended usages: %w", err)
			}
			extraExtensions = append(extraExtensions, extendedUsages)
		}
	}

	// NOTE(@inteon): opts.EncodeBasicConstraintsInRequest is a temporary solution and will
	// be removed/ replaced in a future release.
	if opts.EncodeBasicConstraintsInRequest {
		basicExtension, err := MarshalBasicConstraints(crt.Spec.IsCA, nil)
		if err != nil {
			return nil, err
		}
		extraExtensions = append(extraExtensions, basicExtension)
	}

	if opts.EncodeNameConstraints && crt.Spec.NameConstraints != nil {
		nameConstraints := &NameConstraints{}

		if crt.Spec.NameConstraints.Permitted != nil {
			nameConstraints.PermittedDNSDomains = crt.Spec.NameConstraints.Permitted.DNSDomains
			nameConstraints.PermittedIPRanges, err = parseCIDRs(crt.Spec.NameConstraints.Permitted.IPRanges)
			if err != nil {
				return nil, err
			}
			nameConstraints.PermittedEmailAddresses = crt.Spec.NameConstraints.Permitted.EmailAddresses
			nameConstraints.PermittedURIDomains = crt.Spec.NameConstraints.Permitted.URIDomains
		}

		if crt.Spec.NameConstraints.Excluded != nil {
			nameConstraints.ExcludedDNSDomains = crt.Spec.NameConstraints.Excluded.DNSDomains
			nameConstraints.ExcludedIPRanges, err = parseCIDRs(crt.Spec.NameConstraints.Excluded.IPRanges)
			if err != nil {
				return nil, err
			}
			nameConstraints.ExcludedEmailAddresses = crt.Spec.NameConstraints.Excluded.EmailAddresses
			nameConstraints.ExcludedURIDomains = crt.Spec.NameConstraints.Excluded.URIDomains
		}

		if !nameConstraints.IsEmpty() {
			extension, err := MarshalNameConstraints(nameConstraints, crt.Spec.NameConstraints.Critical)
			if err != nil {
				return nil, err
			}

			extraExtensions = append(extraExtensions, extension)
		}
	}

	cr := &x509.CertificateRequest{
		// Version 0 is the only one defined in the PKCS#10 standard, RFC2986.
		// This value isn't used by Go at the time of writing.
		// https://datatracker.ietf.org/doc/html/rfc2986#section-4
		Version:            0,
		SignatureAlgorithm: sigAlgo,
		PublicKeyAlgorithm: pubKeyAlgo,
		RawSubject:         asn1Subject,
		ExtraExtensions:    extraExtensions,
	}

	return cr, nil
}

// SignCertificate returns a signed *x509.Certificate given a template
// *x509.Certificate crt and an issuer.
// publicKey is the public key of the signee, and signerKey is the private
// key of the signer.
// It returns a PEM encoded copy of the Certificate as well as a *x509.Certificate
// which can be used for reading the encoded values.
func SignCertificate(template *x509.Certificate, issuerCert *x509.Certificate, publicKey crypto.PublicKey, signerKey any) ([]byte, *x509.Certificate, error) {
	typedSigner, ok := signerKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("didn't get an expected Signer in call to SignCertificate")
	}

	var pubKeyAlgo x509.PublicKeyAlgorithm
	var sigAlgoArg any

	// NB: can't rely on issuerCert.Public or issuercert.PublicKeyAlgorithm being set reliably;
	// but we know that signerKey.Public() will work!
	switch pubKey := typedSigner.Public().(type) {
	case *rsa.PublicKey:
		pubKeyAlgo = x509.RSA

		// Size is in bytes so multiply by 8 to get bits because they're more familiar
		// This is technically not portable but if you're using cert-manager on a platform
		// with bytes that don't have 8 bits, you've got bigger problems than this!
		sigAlgoArg = pubKey.Size() * 8

	case *ecdsa.PublicKey:
		pubKeyAlgo = x509.ECDSA
		sigAlgoArg = pubKey.Curve

	case ed25519.PublicKey:
		pubKeyAlgo = x509.Ed25519
		sigAlgoArg = nil // ignored by signatureAlgorithmFromPublicKey

	case *mldsa65.PublicKey:
		// ML-DSA uses UnknownPublicKeyAlgorithm as x509 doesn't support it yet
		pubKeyAlgo = x509.UnknownPublicKeyAlgorithm
		sigAlgoArg = nil

	default:
		return nil, nil, fmt.Errorf("unknown public key type on signing certificate: %T", issuerCert.PublicKey)
	}

	var err error
	template.SignatureAlgorithm, err = signatureAlgorithmFromPublicKey(pubKeyAlgo, sigAlgoArg)
	if err != nil {
		return nil, nil, err
	}

	var derBytes []byte

	// Special handling for ML-DSA: x509.CreateCertificate doesn't support it yet
	if _, isMLDSA := typedSigner.(*mldsa65.PrivateKey); isMLDSA {
		derBytes, err = createMLDSACertificate(template, issuerCert, publicKey, typedSigner)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating ML-DSA certificate: %s", err.Error())
		}
	} else {
		derBytes, err = x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, typedSigner)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating x509 certificate: %s", err.Error())
		}
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

// createMLDSACertificate creates a certificate signed with ML-DSA.
// This is a workaround since x509.CreateCertificate doesn't support ML-DSA yet.
// It manually constructs an X.509 certificate structure and signs it with ML-DSA.
func createMLDSACertificate(template *x509.Certificate, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) ([]byte, error) {
	mldsaPriv, ok := priv.(*mldsa65.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ML-DSA type")
	}

	mldsaPub, ok := pub.(*mldsa65.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ML-DSA type")
	}

	// Use the template values that are already set by cert-manager
	// Set defaults only if not provided
	if template.SerialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, fmt.Errorf("failed to generate serial number: %w", err)
		}
		template.SerialNumber = serialNumber
	}

	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-5 * time.Minute)
	}

	if template.NotAfter.IsZero() {
		template.NotAfter = template.NotBefore.Add(90 * 24 * time.Hour)
	}

	// Build complete X.509 certificate structure manually
	// Marshal the subject
	var subjectBytes []byte
	var err error
	if len(template.RawSubject) > 0 {
		subjectBytes = template.RawSubject
	} else {
		subjectBytes, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, fmt.Errorf("failed to marshal subject: %w", err)
		}
	}

	// Get issuer bytes
	var issuerBytes []byte
	if parent != nil && len(parent.RawSubject) > 0 {
		issuerBytes = parent.RawSubject
	} else if parent != nil {
		issuerBytes, err = asn1.Marshal(parent.Subject.ToRDNSequence())
		if err != nil {
			return nil, fmt.Errorf("failed to marshal issuer: %w", err)
		}
	} else {
		// Self-signed: issuer = subject
		issuerBytes = subjectBytes
	}

	// Collect all extensions from the template
	var extensions []pkix.Extension

	// Add SubjectKeyId if set
	if len(template.SubjectKeyId) > 0 {
		skidBytes, err := asn1.Marshal(template.SubjectKeyId)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SubjectKeyId: %w", err)
		}
		extensions = append(extensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 14}, // subjectKeyIdentifier
			Value: skidBytes,
		})
	}

	// Add AuthorityKeyId if set
	if len(template.AuthorityKeyId) > 0 {
		// AuthorityKeyIdentifier is more complex - it's a SEQUENCE with keyIdentifier [0] IMPLICIT OCTET STRING
		type authKeyId struct {
			KeyIdentifier []byte `asn1:"optional,tag:0"`
		}
		akid := authKeyId{KeyIdentifier: template.AuthorityKeyId}
		akidBytes, err := asn1.Marshal(akid)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal AuthorityKeyId: %w", err)
		}
		extensions = append(extensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 35}, // authorityKeyIdentifier
			Value: akidBytes,
		})
	}

	// Add KeyUsage if set
	if template.KeyUsage != 0 {
		kuBytes, err := marshalKeyUsage(template.KeyUsage)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal KeyUsage: %w", err)
		}
		extensions = append(extensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // keyUsage
			Critical: true,
			Value:    kuBytes,
		})
	}

	// Add BasicConstraints if set
	if template.BasicConstraintsValid {
		bcBytes, err := marshalBasicConstraints(template.IsCA, template.MaxPathLen, template.MaxPathLenZero)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal BasicConstraints: %w", err)
		}
		extensions = append(extensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // basicConstraints
			Critical: true,
			Value:    bcBytes,
		})
	}

	// Add all ExtraExtensions from template (includes SANs, etc.)
	extensions = append(extensions, template.ExtraExtensions...)

	// Build TBSCertificate
	pubKeyBytes := mldsaPub.Bytes()
	tbsCert := struct {
		Version            int `asn1:"explicit,default:0,tag:0"`
		SerialNumber       *big.Int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             asn1.RawValue
		Validity           struct {
			NotBefore, NotAfter time.Time
		}
		Subject   asn1.RawValue
		PublicKey struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}{
		Version:      2, // X.509 v3
		SerialNumber: template.SerialNumber,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, // ML-DSA-65 OID (FIPS 204)
		},
		Issuer:     asn1.RawValue{FullBytes: issuerBytes},
		Subject:    asn1.RawValue{FullBytes: subjectBytes},
		Extensions: extensions,
	}

	tbsCert.Validity.NotBefore = template.NotBefore
	tbsCert.Validity.NotAfter = template.NotAfter

	tbsCert.PublicKey.Algorithm = pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, // ML-DSA-65 OID (FIPS 204)
	}
	tbsCert.PublicKey.PublicKey = asn1.BitString{
		Bytes:     pubKeyBytes,
		BitLength: len(pubKeyBytes) * 8,
	}

	// Marshal TBSCertificate
	tbsBytes, err := asn1.Marshal(tbsCert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Sign with ML-DSA
	signature, err := mldsaPriv.Sign(nil, tbsBytes, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Build final certificate
	certStruct := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate: asn1.RawValue{FullBytes: tbsBytes},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, // ML-DSA-65 OID (FIPS 204)
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	certDER, err := asn1.Marshal(certStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	return certDER, nil
}

// marshalKeyUsage marshals KeyUsage for X.509 extension
func marshalKeyUsage(ku x509.KeyUsage) ([]byte, error) {
	// KeyUsage is a bit string in ASN.1
	var a [2]byte
	a[0] = byte(ku)
	a[1] = byte(ku >> 8)

	// Find the last set bit
	ret := a[0:]
	if a[1] != 0 {
		ret = a[:]
	}

	return asn1.Marshal(asn1.BitString{Bytes: ret, BitLength: 9})
}

// marshalBasicConstraints marshals BasicConstraints for X.509 extension
func marshalBasicConstraints(isCA bool, maxPathLen int, maxPathLenZero bool) ([]byte, error) {
	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}

	bc := basicConstraints{IsCA: isCA}
	if isCA {
		if maxPathLenZero {
			bc.MaxPathLen = 0
		} else if maxPathLen > 0 {
			bc.MaxPathLen = maxPathLen
		} else {
			bc.MaxPathLen = -1 // unlimited
		}
	}

	return asn1.Marshal(bc)
}

// SignCSRTemplate signs a certificate template usually based upon a CSR. This
// function expects all fields to be present in the certificate template,
// including its public key.
// It returns the PEM bundle containing certificate data and the CA data, encoded in PEM format.
func SignCSRTemplate(caCerts []*x509.Certificate, caPrivateKey crypto.Signer, template *x509.Certificate) (PEMBundle, error) {
	if len(caCerts) == 0 {
		return PEMBundle{}, errors.New("no CA certificates given to sign CSR template")
	}

	issuingCACert := caCerts[0]

	_, cert, err := SignCertificate(template, issuingCACert, template.PublicKey, caPrivateKey)
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
// For MLDSA65 keys, it manually creates and signs the CSR since x509 doesn't support them yet.
func EncodeCSR(template *x509.CertificateRequest, key crypto.Signer) ([]byte, error) {
	// Special handling for MLDSA65 keys
	if mldsaKey, ok := key.(*mldsa65.PrivateKey); ok {
		return encodeMLDSA65CSR(template, mldsaKey)
	}

	// Standard x509 handling for other key types
	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("error creating x509 certificate: %s", err.Error())
	}

	return derBytes, nil
}

// encodeMLDSA65CSR creates a CSR for MLDSA65 keys manually since x509 doesn't support them yet
func encodeMLDSA65CSR(template *x509.CertificateRequest, key *mldsa65.PrivateKey) ([]byte, error) {
	// ML-DSA-65 OID (FIPS 204)
	mldsaOid := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

	// Get the public key bytes
	pubKey := key.Public().(*mldsa65.PublicKey)
	publicKeyBytes := pubKey.Bytes()

	// Build SubjectPublicKeyInfo for CSR
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: mldsaOid,
		},
		PublicKey: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: len(publicKeyBytes) * 8,
		},
	}
	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SubjectPublicKeyInfo for CSR: %w", err)
	}

	// Marshal subject
	var subjectBytes []byte
	if len(template.RawSubject) > 0 {
		subjectBytes = template.RawSubject
	} else {
		subjectBytes, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, fmt.Errorf("failed to marshal subject for CSR: %w", err)
		}
	}

	// Build attributes
	var attributes []interface{}

	// If we have extensions to add, create an extensionRequest attribute
	if len(template.Extensions) > 0 || len(template.ExtraExtensions) > 0 ||
		len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 ||
		len(template.IPAddresses) > 0 || len(template.URIs) > 0 {

		var extensions []pkix.Extension
		extensions = append(extensions, template.Extensions...)
		extensions = append(extensions, template.ExtraExtensions...)

		// Add SANs if present
		if len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 ||
			len(template.IPAddresses) > 0 || len(template.URIs) > 0 {
			gns := GeneralNames{
				DNSNames:    template.DNSNames,
				IPAddresses: template.IPAddresses,
				RFC822Names: template.EmailAddresses,
				UniformResourceIdentifiers: func() []string {
					var uris []string
					for _, uri := range template.URIs {
						if uri != nil {
							uris = append(uris, uri.String())
						}
					}
					return uris
				}(),
			}
			hasSubject := len(subjectBytes) > 2 // More than just empty SEQUENCE
			sanExtension, err := MarshalSANs(gns, hasSubject)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal SAN extension for CSR: %w", err)
			}
			extensions = append(extensions, sanExtension)
		}

		// Extensions wrapped in SEQUENCE
		extensionsBytes, err := asn1.Marshal(extensions)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal extensions for CSR: %w", err)
		}

		// Attribute for Extension Request (OID 1.2.840.113549.1.9.14)
		extensionRequestOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

		// The attribute value needs to be a SET containing the SEQUENCE of extensions
		attribute := struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}{
			Type: extensionRequestOID,
			Values: []asn1.RawValue{
				{FullBytes: extensionsBytes},
			},
		}

		attributes = append(attributes, attribute)
	}

	// Build CertificationRequestInfo
	csrInfo := struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []interface{} `asn1:"tag:0"`
	}{
		Version:    0, // v1
		Subject:    asn1.RawValue{FullBytes: subjectBytes},
		PublicKey:  asn1.RawValue{FullBytes: spkiBytes},
		Attributes: attributes,
	}

	csrInfoBytes, err := asn1.Marshal(csrInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CertificationRequestInfo: %w", err)
	}

	// Sign the CSR using SignTo
	csrSignature := make([]byte, mldsa65.SignatureSize)
	err = mldsa65.SignTo(key, csrInfoBytes, nil, false, csrSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}

	// Build the final CSR
	csr := struct {
		CertificationRequestInfo asn1.RawValue
		SignatureAlgorithm       pkix.AlgorithmIdentifier
		Signature                asn1.BitString
	}{
		CertificationRequestInfo: asn1.RawValue{FullBytes: csrInfoBytes},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: mldsaOid,
		},
		Signature: asn1.BitString{
			Bytes:     csrSignature,
			BitLength: len(csrSignature) * 8,
		},
	}

	csrBytes, err := asn1.Marshal(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR: %w", err)
	}

	return csrBytes, nil
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

var keyAlgorithms = map[v1.PrivateKeyAlgorithm]x509.PublicKeyAlgorithm{
	v1.RSAKeyAlgorithm:     x509.RSA,
	v1.ECDSAKeyAlgorithm:   x509.ECDSA,
	v1.Ed25519KeyAlgorithm: x509.Ed25519,
	// ML-DSA uses UnknownPublicKeyAlgorithm as x509 doesn't have ML-DSA type yet
	v1.MLDSA65KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
}
var sigAlgorithms = map[v1.SignatureAlgorithm]x509.SignatureAlgorithm{
	v1.SHA256WithRSA:   x509.SHA256WithRSA,
	v1.SHA384WithRSA:   x509.SHA384WithRSA,
	v1.SHA512WithRSA:   x509.SHA512WithRSA,
	v1.ECDSAWithSHA256: x509.ECDSAWithSHA256,
	v1.ECDSAWithSHA384: x509.ECDSAWithSHA384,
	v1.ECDSAWithSHA512: x509.ECDSAWithSHA512,
	v1.PureEd25519:     x509.PureEd25519,
	// ML-DSA uses UnknownSignatureAlgorithm as x509 doesn't have ML-DSA type yet
	v1.PureMLDSA65: x509.UnknownSignatureAlgorithm,
}

// SignatureAlgorithm will determine the appropriate signature algorithm for
// the given certificate.
// Adapted from https://github.com/cloudflare/cfssl/blob/master/csr/csr.go#L102
func SignatureAlgorithm(crt *v1.Certificate) (x509.PublicKeyAlgorithm, x509.SignatureAlgorithm, error) {
	var pubKeyAlgo x509.PublicKeyAlgorithm
	var specAlgorithm v1.PrivateKeyAlgorithm
	var specKeySize int

	if crt.Spec.PrivateKey != nil {
		specAlgorithm = crt.Spec.PrivateKey.Algorithm
		specKeySize = crt.Spec.PrivateKey.Size
	}

	var sigAlgoArg any

	var ok bool
	if specAlgorithm == "" {
		pubKeyAlgo = x509.RSA
	} else {
		pubKeyAlgo, ok = keyAlgorithms[specAlgorithm]
		if !ok {
			return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported algorithm specified: %s. should be either 'rsa', 'ecdsa', 'ed25519', or 'mldsa65'", crt.Spec.PrivateKey.Algorithm)
		}
	}

	var sigAlgo x509.SignatureAlgorithm
	if crt.Spec.SignatureAlgorithm != "" {
		sigAlgo, ok = sigAlgorithms[crt.Spec.SignatureAlgorithm]
		if !ok {
			return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported signature algorithm: %s", crt.Spec.SignatureAlgorithm)
		}
		return pubKeyAlgo, sigAlgo, nil
	}

	switch pubKeyAlgo {
	case x509.RSA:
		if specKeySize == 0 {
			sigAlgoArg = MinRSAKeySize
		} else {
			sigAlgoArg = specKeySize
		}
	case x509.ECDSA:
		switch specKeySize {
		case 521:
			sigAlgoArg = elliptic.P521()
		case 384:
			sigAlgoArg = elliptic.P384()
		case 256, 0:
			sigAlgoArg = elliptic.P256()
		default:
			return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported ecdsa keysize specified: %d", crt.Spec.PrivateKey.Size)
		}
	default:
		// ok
	}

	sigAlgo, err := signatureAlgorithmFromPublicKey(pubKeyAlgo, sigAlgoArg)
	if err != nil {
		return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm, err
	}

	return pubKeyAlgo, sigAlgo, nil
}

// signatureAlgorithmFromPublicKey takes a public key type and an argument specific to that public
// key, and returns an appropriate signature algorithm for that key.
// If alg is x509.RSA, arg must be an integer key size in bits
// If alg is x509.ECDSA, arg must be an elliptic.Curve
// If alg is x509.Ed25519, arg is ignored
// If alg is x509.UnknownPublicKeyAlgorithm (used for ML-DSA), returns UnknownSignatureAlgorithm
// All other algorithms and args cause an error
// The signature algorithms returned by this function are to some degree a matter of preference. The
// choices here are motivated by what is common and what is required by bodies such as the US DoD.
func signatureAlgorithmFromPublicKey(alg x509.PublicKeyAlgorithm, arg any) (x509.SignatureAlgorithm, error) {
	var signatureAlgorithm x509.SignatureAlgorithm

	switch alg {
	case x509.RSA:
		size, ok := arg.(int)
		if !ok {
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("expected to get an integer key size for RSA key but got %T", arg)
		}

		switch {
		case size >= 4096:
			signatureAlgorithm = x509.SHA512WithRSA

		case size >= 3072:
			signatureAlgorithm = x509.SHA384WithRSA

		case size >= 2048:
			signatureAlgorithm = x509.SHA256WithRSA

		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("invalid size %d for RSA key on signing certificate", size)
		}

	case x509.ECDSA:
		curve, ok := arg.(elliptic.Curve)
		if !ok {
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("expected to get an ECDSA curve for ECDSA key but got %T", arg)
		}

		switch curve {
		case elliptic.P521():
			signatureAlgorithm = x509.ECDSAWithSHA512

		case elliptic.P384():
			signatureAlgorithm = x509.ECDSAWithSHA384

		case elliptic.P256():
			signatureAlgorithm = x509.ECDSAWithSHA256

		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("unknown / unsupported curve attached to ECDSA signing certificate")
		}

	case x509.Ed25519:
		signatureAlgorithm = x509.PureEd25519

	case x509.UnknownPublicKeyAlgorithm:
		// ML-DSA uses UnknownPublicKeyAlgorithm as a placeholder
		// The actual signature is handled by the crypto.Signer interface
		signatureAlgorithm = x509.UnknownSignatureAlgorithm

	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("got unsupported public key type when trying to calculate signature algorithm")
	}

	return signatureAlgorithm, nil
}
