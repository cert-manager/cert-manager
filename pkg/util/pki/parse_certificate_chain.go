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
	"crypto/x509"
	"slices"

	"github.com/cert-manager/cert-manager/pkg/util/errors"
)

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
// well as the PEM-encoded CA certificate.
//
// The CA (CAPEM) may not be a true root, but the highest intermediate certificate.
// The certificate is chosen as follows:
//   - If the chain has a self-signed root, the root certificate.
//   - If the chain has no self-signed root and has > 1 certificates, the highest certificate in the chain.
//   - If the chain has no self-signed root and has == 1 certificate, nil.
//
// The certificate chain (ChainPEM) starts with the leaf certificate and ends with the
// highest certificate in the chain which is not self-signed. Self-signed certificates
// are not included in the chain because we are certain they are known and trusted by the
// client already.
//
// This function removes duplicate certificate entries as well as comments and
// unnecessary white space.
//
// An error is returned if the passed bundle is not a valid single chain,
// the bundle is malformed, or the chain is broken.
func ParseSingleCertificateChain(certs []*x509.Certificate) (PEMBundle, error) {
	for _, cert := range certs {
		if cert == nil {
			return PEMBundle{}, errors.NewInvalidData("certificate chain contains nil certificate")
		}

		if len(cert.Raw) == 0 {
			return PEMBundle{}, errors.NewInvalidData("certificate chain contains certificate without Raw set")
		}
	}

	{
		// De-duplicate certificates. This moves "complicated" logic away from
		// consumers and into a shared function, who would otherwise have to do this
		// anyway.
		// For lots of certificates, the time complexity is O(n log n).
		uniqueCerts := append([]*x509.Certificate{}, certs...)
		slices.SortFunc(uniqueCerts, func(a, b *x509.Certificate) int {
			return bytes.Compare(a.Raw, b.Raw)
		})
		uniqueCerts = slices.CompactFunc(uniqueCerts, func(a, b *x509.Certificate) bool {
			return bytes.Equal(a.Raw, b.Raw)
		})
		certs = uniqueCerts
	}

	// To prevent a malicious input from causing a DoS, we limit the number of unique
	// certificates to 1000. This helps us avoid issues with O(n^2) time complexity
	// in the algorithm below.
	if len(certs) > 1000 {
		return PEMBundle{}, errors.NewInvalidData("certificate chain is too long, must be less than 1000 certificates")
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
	// chain. If no match is found after a pass, then the list can never be reduced
	// to a single chain and we error.
	// For lots of certificates, the time complexity is O(n^2).
	for {
		// If a single list is left, then we have built the entire chain. Stop
		// iterating.
		if len(chains) == 1 {
			break
		}

		// If we were not able to merge two chains in this pass, then the chain is
		// broken and cannot be built. Error.
		mergedTwoChains := false

		// Pop the last chain off the list and attempt to find a chain it can be
		// merged with.
		lastChain := chains[len(chains)-1]
		chains = chains[:len(chains)-1]

		for i, chain := range chains {
			// attempt to add both chains together
			chain, ok := lastChain.tryMergeChain(chain)
			if ok {
				// If adding the chains together was successful, replace the chain at
				// index i with the new chain.
				chains[i] = chain
				mergedTwoChains = true
				break
			}
		}

		// If no chains were merged in this pass, the chain can never be built as a
		// single list. Error.
		if !mergedTwoChains {
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
//	     head                                         tail
//	+------+-------+      +------+-------+      +------+-------+
//	|      |       |      |      |       |      |      |       |
//	|      |  sig ------->|  C   |  sig ------->|  P   |       |
//	|      |       |      |      |       |      |      |       |
//	+------+-------+      +------+-------+      +------+-------+
//	leaf certificate                            root certificate
//
// The function returns false if the chains A and B are not gluable.
func (a *chainNode) tryMergeChain(b *chainNode) (*chainNode, bool) {
	bRoot := b.root()

	// b's root has been signed by a. Add a as parent of b's root.
	if bytes.Equal(bRoot.cert.RawIssuer, a.cert.RawSubject) &&
		bRoot.cert.CheckSignatureFrom(a.cert) == nil {
		bRoot.issuer = a
		return b, true
	}

	aRoot := a.root()

	// a's root has been signed by b. Add b as parent of a's root.
	if bytes.Equal(aRoot.cert.RawIssuer, b.cert.RawSubject) &&
		aRoot.cert.CheckSignatureFrom(b.cert) == nil {
		aRoot.issuer = b
		return a, true
	}

	// Chains cannot be added together.
	return a, false
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
