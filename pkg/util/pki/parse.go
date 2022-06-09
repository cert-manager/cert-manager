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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/go-ldap/ldap/v3"
)

// DecodePrivateKeyBytes will decode a PEM encoded private key into a crypto.Signer.
// It supports ECDSA and RSA private keys only. All other types will return err.
func DecodePrivateKeyBytes(keyBytes []byte) (crypto.Signer, error) {
	// decode the private key pem
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.NewInvalidData("error decoding private key PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing pkcs#8 private key: %s", err.Error())
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.NewInvalidData("error parsing pkcs#8 private key: invalid key type")
		}
		return signer, nil
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

// DecodePKCS1PrivateKeyBytes will decode a PEM encoded RSA private key.
func DecodePKCS1PrivateKeyBytes(keyBytes []byte) (*rsa.PrivateKey, error) {
	// decode the private key pem
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.NewInvalidData("error decoding private key PEM block")
	}
	// parse the private key
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.NewInvalidData("error parsing private key: %s", err.Error())
	}
	// validate the private key
	if err = key.Validate(); err != nil {
		return nil, errors.NewInvalidData("private key failed validation: %s", err.Error())
	}
	return key, nil
}

// DecodeX509CertificateChainBytes will decode a PEM encoded x509 Certificate chain.
func DecodeX509CertificateChainBytes(certBytes []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var block *pem.Block

	for {
		// decode the tls certificate pem
		block, certBytes = pem.Decode(certBytes)
		if block == nil {
			break
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing TLS certificate: %s", err.Error())
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.NewInvalidData("error decoding certificate PEM block")
	}

	return certs, nil
}

// DecodeX509CertificateBytes will decode a PEM encoded x509 Certificate.
func DecodeX509CertificateBytes(certBytes []byte) (*x509.Certificate, error) {
	certs, err := DecodeX509CertificateChainBytes(certBytes)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

// DecodeX509CertificateRequestBytes will decode a PEM encoded x509 Certificate Request.
func DecodeX509CertificateRequestBytes(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrBytes)
	if block == nil {
		return nil, errors.NewInvalidData("error decoding certificate request PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

// PEMBundle includes the PEM encoded X.509 certificate chain and CA. CAPEM
// contains either 1 CA certificate, or is empty if only a single certificate
// exists in the chain.
type PEMBundle struct {
	CAPEM    []byte
	ChainPEM []byte
}

type chainNode struct {
	cert   *x509.Certificate
	issuer *chainNode
}

// ParseSingleCertificateChainPEM decodes a PEM encoded certificate chain before
// calling ParseSingleCertificateChainPEM
func ParseSingleCertificateChainPEM(pembundle []byte) (PEMBundle, error) {
	certs, err := DecodeX509CertificateChainBytes(pembundle)
	if err != nil {
		return PEMBundle{}, err
	}
	return ParseSingleCertificateChain(certs)
}

// ParseSingleCertificateChain returns the PEM-encoded chain of certificates as
// well as the PEM-encoded CA certificate. The certificate chain contains the
// leaf certificate first.
//
// The CA may not be a true root, but the highest intermediate certificate.
// The returned CA may be empty if a single certificate was passed.
//
// This function removes duplicate certificate entries as well as comments and
// unnecessary white space.
//
// An error is returned if the passed bundle is not a valid flat tree chain,
// the bundle is malformed, or the chain is broken.
func ParseSingleCertificateChain(certs []*x509.Certificate) (PEMBundle, error) {
	// De-duplicate certificates. This moves "complicated" logic away from
	// consumers and into a shared function, who would otherwise have to do this
	// anyway.
	for i := 0; i < len(certs)-1; i++ {
		for j := 1; j < len(certs); j++ {
			if i == j {
				continue
			}
			if certs[i].Equal(certs[j]) {
				certs = append(certs[:j], certs[j+1:]...)
			}
		}
	}

	// A certificate chain can be well described as a linked list. Here we build
	// multiple lists that contain a single node, each being a single certificate
	// that was passed.
	var chains []*chainNode
	for i := range certs {
		chains = append(chains, &chainNode{cert: certs[i]})
	}

	// The task is to build a single list which represents a single certificate
	// chain. The strategy is to iteratively attempt to join items in the list to
	// build this single chain. Once we have a single list, we have built the
	// chain. If the number of lists do not decrease after a pass, then the list
	// can never be reduced to a single chain and we error.
	for {
		// If a single list is left, then we have built the entire chain. Stop
		// iterating.
		if len(chains) == 1 {
			break
		}

		// lastChainsLength is used to ensure that at every pass, the number of
		// tested chains gets smaller.
		lastChainsLength := len(chains)
		for i := 0; i < len(chains)-1; i++ {
			for j := 1; j < len(chains); j++ {
				if i == j {
					continue
				}

				// attempt to add both chains together
				chain, ok := chains[i].tryMergeChain(chains[j])
				if ok {
					// If adding the chains together was successful, remove inner chain from
					// list
					chains = append(chains[:j], chains[j+1:]...)
				}

				chains[i] = chain
			}
		}

		// If no chains were merged in this pass, the chain can never be built as a
		// single list. Error.
		if lastChainsLength == len(chains) {
			return PEMBundle{}, errors.NewInvalidData("certificate chain is malformed or broken")
		}
	}

	// There is only a single chain left at index 0. Return chain as PEM.
	return chains[0].toBundleAndCA()
}

// toBundleAndCA will return the PEM bundle of this chain.
func (c *chainNode) toBundleAndCA() (PEMBundle, error) {
	var (
		certs []*x509.Certificate
		ca    *x509.Certificate
	)

	for {
		// If the issuer is nil, we have hit the root of the chain. Assign the CA
		// to this certificate and stop traversing. If the certificate at the root
		// of the chain is not self-signed (i.e. is not a root CA), then also append
		// that certificate to the chain.

		// Root certificates are omitted from the chain as per
		// https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2
		// > [T]he self-signed certificate that specifies the root certificate authority
		// > MAY be omitted from the chain, under the assumption that the remote end must
		// > already possess it in order to validate it in any case.

		if c.issuer == nil {
			if len(certs) > 0 && !isSelfSignedCertificate(c.cert) {
				certs = append(certs, c.cert)
			}

			ca = c.cert
			break
		}

		// Add this node's certificate to the list at the end. Ready to check
		// next node up.
		certs = append(certs, c.cert)
		c = c.issuer
	}

	caPEM, err := EncodeX509(ca)
	if err != nil {
		return PEMBundle{}, err
	}

	// If no certificates parsed, then CA is the only certificate and should be
	// the chain. If the CA is also self-signed, then by definition it's also the
	// issuer and so can be placed in CAPEM too.
	if len(certs) == 0 {
		if isSelfSignedCertificate(ca) {
			return PEMBundle{ChainPEM: caPEM, CAPEM: caPEM}, nil
		}

		return PEMBundle{ChainPEM: caPEM}, nil
	}

	// Encode full certificate chain
	chainPEM, err := EncodeX509Chain(certs)
	if err != nil {
		return PEMBundle{}, err
	}

	// Return chain and ca
	return PEMBundle{CAPEM: caPEM, ChainPEM: chainPEM}, nil
}

// tryMergeChain glues two chains A and B together by adding one on top of
// the other. The function tries both gluing A on top of B and B on top of
// A, which is why the argument order for the two input chains does not
// matter.
//
// Gluability: We say that the chains A and B are glueable when either the
// leaf certificate of A can be verified using the root certificate of B,
// or that the leaf certificate of B can be verified using the root certificate
// of A.
//
// A leaf certificate C (as in "child") is verified by a certificate P
// (as in "parent"), when they satisfy C.CheckSignatureFrom(P). In the
// following diagram, C.CheckSignatureFrom(P) is satisfied, i.e., the
// signature ("sig") on the certificate C can be verified using the parent P:
//
//       head                                         tail
//  +------+-------+      +------+-------+      +------+-------+
//  |      |       |      |      |       |      |      |       |
//  |      |  sig ------->|  C   |  sig ------->|  P   |       |
//  |      |       |      |      |       |      |      |       |
//  +------+-------+      +------+-------+      +------+-------+
//  leaf certificate                            root certificate
//
// The function returns false if the chains A and B are not gluable.
func (c *chainNode) tryMergeChain(chain *chainNode) (*chainNode, bool) {
	// The given chain's root has been signed by this node. Add this node on top
	// of the given chain.
	if chain.root().cert.CheckSignatureFrom(c.cert) == nil {
		chain.root().issuer = c
		return chain, true
	}

	// The given chain is the issuer of the root of this node. Add the given
	// chain on top of the root of this node.
	if c.root().cert.CheckSignatureFrom(chain.cert) == nil {
		c.root().issuer = chain
		return c, true
	}

	// Chains cannot be added together.
	return c, false
}

// Return the root most node of this chain.
func (c *chainNode) root() *chainNode {
	for c.issuer != nil {
		c = c.issuer
	}

	return c
}

// isSelfSignedCertificate returns true if the given X.509 certificate has been
// signed by itself, which would make it a "root" certificate.
func isSelfSignedCertificate(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

var OIDConstants = struct {
	Country            []int
	Organization       []int
	OrganizationalUnit []int
	CommonName         []int
	SerialNumber       []int
	Locality           []int
	Province           []int
	StreetAddress      []int
}{
	Country:            []int{2, 5, 4, 6},
	Organization:       []int{2, 5, 4, 10},
	OrganizationalUnit: []int{2, 5, 4, 11},
	CommonName:         []int{2, 5, 4, 3},
	SerialNumber:       []int{2, 5, 4, 5},
	Locality:           []int{2, 5, 4, 7},
	Province:           []int{2, 5, 4, 8},
	StreetAddress:      []int{2, 5, 4, 9},
}

// Copied from pkix.attributeTypeNames and inverted. (Sadly it is private.)
// Source: https://cs.opensource.google/go/go/+/refs/tags/go1.18.2:src/crypto/x509/pkix/pkix.go;l=26
var attributeTypeNames = map[string][]int{
	"C":            OIDConstants.Country,
	"O":            OIDConstants.Organization,
	"OU":           OIDConstants.OrganizationalUnit,
	"CN":           OIDConstants.CommonName,
	"SERIALNUMBER": OIDConstants.SerialNumber,
	"L":            OIDConstants.Locality,
	"ST":           OIDConstants.Province,
	"STREET":       OIDConstants.StreetAddress,
}

func ParseSubjectStringToRdnSequence(subject string) (pkix.RDNSequence, error) {

	dns, err := ldap.ParseDN(subject)
	if err != nil {
		return nil, err
	}

	// Traverse the parsed RDNSequence in REVERSE order as RDNs in String format are expected to be written in reverse order.
	// Meaning, a string of "CN=Foo,OU=Bar,O=Baz" actually should have "O=Baz" as the first element in the RDNSequence.
	var rdns pkix.RDNSequence
	for i := range dns.RDNs {
		ldapRelativeDN := dns.RDNs[len(dns.RDNs)-i-1]

		var atvs []pkix.AttributeTypeAndValue
		for _, ldapATV := range ldapRelativeDN.Attributes {

			atvs = append(atvs, pkix.AttributeTypeAndValue{
				Type:  attributeTypeNames[ldapATV.Type],
				Value: ldapATV.Value,
			})

		}
		rdns = append(rdns, atvs)
	}
	return rdns, nil

}

func ParseSubjectStringToRawDerBytes(subject string) ([]byte, error) {
	rdnSequenceFromLiteralString, err := ParseSubjectStringToRdnSequence(subject)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(rdnSequenceFromLiteralString)

}
