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
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	stdpem "encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/cert-manager/cert-manager/internal/pem"
	"github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// DecodePrivateKeyBytes will decode a PEM encoded private key into a crypto.Signer.
// It supports ECDSA, RSA, EdDSA and ML-DSA-65 private keys. All other types will return err.
func DecodePrivateKeyBytes(keyBytes []byte) (crypto.Signer, error) {
	// decode the private key pem
	block, _, err := pem.SafeDecodePrivateKey(keyBytes)
	if err != nil {
		return nil, errors.NewInvalidData("error decoding private key PEM block: %s", err.Error())
	}

	switch block.Type {
	case "PRIVATE KEY":
		// Try standard PKCS8 parsing first (RSA, ECDSA, Ed25519)
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, errors.NewInvalidData("error parsing pkcs#8 private key: invalid key type")
			}
			return signer, nil
		}

		// If standard PKCS8 parsing fails, try to parse as ML-DSA-65
		// ML-DSA keys are encoded in PKCS#8 format with OID 2.16.840.1.101.3.4.3.18
		mldsaKey, mldsaErr := parseMLDSAPKCS8PrivateKey(block.Bytes)
		if mldsaErr == nil {
			return mldsaKey, nil
		}

		// If both failed, return the original PKCS8 error
		return nil, errors.NewInvalidData("error parsing pkcs#8 private key: %s", err.Error())

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing ecdsa private key: %s", err.Error())
		}

		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing rsa private key: %s", err.Error())
		}

		err = key.Validate()
		if err != nil {
			return nil, errors.NewInvalidData("rsa private key failed validation: %s", err.Error())
		}
		return key, nil
	default:
		return nil, errors.NewInvalidData("unknown private key type: %s", block.Type)
	}
}

// parseMLDSAPKCS8PrivateKey parses a PKCS#8 encoded ML-DSA-65 private key.
// The PKCS#8 structure contains the ML-DSA OID and the raw private key bytes.
func parseMLDSAPKCS8PrivateKey(pkcs8Bytes []byte) (*mldsa65.PrivateKey, error) {
	// Parse the PKCS#8 structure
	var pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}

	_, err := asn1.Unmarshal(pkcs8Bytes, &pkcs8)
	if err != nil {
		return nil, err
	}

	// Check if this is an ML-DSA-65 key (OID: 2.16.840.1.101.3.4.3.18)
	mldsaOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	if !pkcs8.Algo.Algorithm.Equal(mldsaOID) {
		return nil, errors.NewInvalidData("not an ML-DSA-65 private key")
	}

	// Create ML-DSA key from the raw bytes
	key := new(mldsa65.PrivateKey)
	err = key.UnmarshalBinary(pkcs8.PrivateKey)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func decodeMultipleCerts(certBytes []byte, decodeFn func([]byte) (*stdpem.Block, []byte, error)) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var block *stdpem.Block

	for {
		var err error

		// decode the tls certificate pem
		block, certBytes, err = decodeFn(certBytes)
		if err != nil {
			if err == pem.ErrNoPEMData {
				break
			}

			return nil, err
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing X.509 certificate: %s", err.Error())
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.NewInvalidData("error decoding certificate PEM block: no valid certificates found")
	}

	return certs, nil
}

// DecodeX509CertificateChainBytes will decode a PEM encoded x509 Certificate chain with a tight
// size limit to reduce the risk of DoS attacks. If you need to decode many certificates, use
// DecodeX509CertificateSetBytes instead.
func DecodeX509CertificateChainBytes(certBytes []byte) ([]*x509.Certificate, error) {
	return decodeMultipleCerts(certBytes, pem.SafeDecodeCertificateChain)
}

// DecodeX509CertificateSetBytes will decode a concatenated set of PEM encoded x509 Certificates,
// with generous size limits to enable parsing of TLS trust bundles.
// If you need to decode a single certificate chain, use DecodeX509CertificateChainBytes instead.
func DecodeX509CertificateSetBytes(certBytes []byte) ([]*x509.Certificate, error) {
	return decodeMultipleCerts(certBytes, pem.SafeDecodeCertificateBundle)
}

// DecodeX509CertificateBytes will decode a PEM encoded x509 Certificate.
func DecodeX509CertificateBytes(certBytes []byte) (*x509.Certificate, error) {
	certs, err := DecodeX509CertificateSetBytes(certBytes)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

// DecodeX509CertificateRequestBytes will decode a PEM encoded x509 Certificate Request.
// parseMLDSACertificateRequest parses a ML-DSA certificate request.
// Since x509.ParseCertificateRequest doesn't support ML-DSA yet, we need to manually parse it.
func parseMLDSACertificateRequest(derBytes []byte) (*x509.CertificateRequest, error) {
	// Define the ML-DSA-65 OID
	mldsaOid := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

	// Parse the outer CSR structure
	var csr struct {
		CertificationRequestInfo asn1.RawValue
		SignatureAlgorithm       pkix.AlgorithmIdentifier
		Signature                asn1.BitString
	}
	rest, err := asn1.Unmarshal(derBytes, &csr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CSR: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after CSR")
	}

	// Check if it's ML-DSA
	if !csr.SignatureAlgorithm.Algorithm.Equal(mldsaOid) {
		// Not an ML-DSA CSR, fall back to standard parsing
		return nil, fmt.Errorf("not an ML-DSA CSR")
	}

	// Parse CertificationRequestInfo
	var csrInfo struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}
	_, err = asn1.Unmarshal(csr.CertificationRequestInfo.FullBytes, &csrInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CertificationRequestInfo: %w", err)
	}

	// Parse subject
	var subject pkix.RDNSequence
	_, err = asn1.Unmarshal(csrInfo.Subject.FullBytes, &subject)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal subject: %w", err)
	}

	// Parse SubjectPublicKeyInfo
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(csrInfo.PublicKey.FullBytes, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SubjectPublicKeyInfo: %w", err)
	}

	// Verify it's ML-DSA public key
	if !spki.Algorithm.Algorithm.Equal(mldsaOid) {
		return nil, fmt.Errorf("public key algorithm is not ML-DSA")
	}

	// Parse the ML-DSA public key
	pubKey := new(mldsa65.PublicKey)
	err = pubKey.UnmarshalBinary(spki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ML-DSA public key: %w", err)
	}

	// Create the x509.CertificateRequest structure
	csrObj := &x509.CertificateRequest{
		Version:            csrInfo.Version,
		Subject:            pkix.Name{},
		PublicKey:          pubKey,
		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
		SignatureAlgorithm: x509.UnknownSignatureAlgorithm,
		Signature:          csr.Signature.Bytes,
		Raw:                derBytes,
		RawTBSCertificateRequest: csr.CertificationRequestInfo.FullBytes,
		RawSubjectPublicKeyInfo:  csrInfo.PublicKey.FullBytes,
		RawSubject:               csrInfo.Subject.FullBytes,
	}

	// Fill in the subject name
	csrObj.Subject.FillFromRDNSequence(&subject)

	// Parse attributes (extensions, SANs, etc.)
	for _, attr := range csrInfo.Attributes {
		var attribute struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		
		_, err := asn1.Unmarshal(attr.FullBytes, &attribute)
		if err != nil {
			continue // Skip attributes that can't be parsed
		}

		// Check for extension request (OID 1.2.840.113549.1.9.14)
		if attribute.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}) {
			for _, value := range attribute.Values {
				// Parse extensions
				var extensions []pkix.Extension
				_, err := asn1.Unmarshal(value.FullBytes, &extensions)
				if err != nil {
					continue
				}

				for _, ext := range extensions {
					// Handle Subject Alternative Names (OID 2.5.29.17)
					if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
						parseMLDSASANExtension(csrObj, ext.Value)
					}
					csrObj.Extensions = append(csrObj.Extensions, ext)
				}
			}
		}
	}

	return csrObj, nil
}

// parseMLDSASANExtension parses Subject Alternative Names from an extension value
func parseMLDSASANExtension(csr *x509.CertificateRequest, extValue []byte) {
	// Parse the SAN extension value
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extValue, &seq)
	if err != nil || len(rest) != 0 {
		return
	}

	if !seq.IsCompound || seq.Tag != asn1.TagSequence || seq.Class != asn1.ClassUniversal {
		return
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return
		}

		switch v.Tag {
		case 2: // dNSName
			csr.DNSNames = append(csr.DNSNames, string(v.Bytes))
		case 1: // rfc822Name (email)
			csr.EmailAddresses = append(csr.EmailAddresses, string(v.Bytes))
		case 7: // iPAddress
			switch len(v.Bytes) {
			case net.IPv4len:
				csr.IPAddresses = append(csr.IPAddresses, net.IP(v.Bytes))
			case net.IPv6len:
				csr.IPAddresses = append(csr.IPAddresses, net.IP(v.Bytes))
			}
		case 6: // uniformResourceIdentifier
			uri, err := url.Parse(string(v.Bytes))
			if err == nil {
				csr.URIs = append(csr.URIs, uri)
			}
		}
	}
}

func DecodeX509CertificateRequestBytes(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _, err := pem.SafeDecodeCSR(csrBytes)
	if err != nil {
		return nil, errors.NewInvalidData("error decoding certificate request PEM block: %s", err)
	}

	// Try to parse as ML-DSA CSR first
	mldsaCSR, mldsaErr := parseMLDSACertificateRequest(block.Bytes)
	if mldsaErr == nil {
		return mldsaCSR, nil
	}

	// Fall back to standard x509 parsing
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		// If both parsers fail, return the standard parser error
		return nil, err
	}

	return csr, nil
}

// CheckCSRSignature verifies the signature on a certificate request.
// It handles both standard x509 CSRs and ML-DSA CSRs.
func CheckCSRSignature(csr *x509.CertificateRequest) error {
	// Check if this is an ML-DSA CSR by examining the public key type
	if mldsaKey, ok := csr.PublicKey.(*mldsa65.PublicKey); ok {
		// ML-DSA CSR - perform custom signature verification
		if !mldsa65.Verify(mldsaKey, csr.RawTBSCertificateRequest, nil, csr.Signature) {
			return fmt.Errorf("ML-DSA CSR signature verification failed")
		}
		return nil
	}

	// Standard CSR - use the built-in CheckSignature method
	return csr.CheckSignature()
}
