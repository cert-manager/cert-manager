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
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/cmrand"
)

type testBundle struct {
	cert *x509.Certificate
	pem  []byte
	pk   crypto.PrivateKey
}

func mustCreateBundle(t *testing.T, issuer *testBundle, name string) *testBundle {
	pk, err := GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, err := cmrand.SerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             pk.Public(),
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	var (
		issuerKey  crypto.PrivateKey
		issuerCert *x509.Certificate
	)

	if issuer == nil {
		// No issuer implies the cert should be self signed
		issuerKey = pk
		issuerCert = template
	} else {
		issuerKey = issuer.pk
		issuerCert = issuer.cert
	}

	certPEM, cert, err := SignCertificate(template, issuerCert, pk.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	return &testBundle{pem: certPEM, cert: cert, pk: pk}
}

func joinPEM(first []byte, rest ...[]byte) []byte {
	for _, b := range rest {
		first = append(first, b...)
	}

	return first
}

func TestParseSingleCertificateChain(t *testing.T) {
	root := mustCreateBundle(t, nil, "root")
	intA1 := mustCreateBundle(t, root, "intA-1")
	intA2 := mustCreateBundle(t, intA1, "intA-2")
	intB1 := mustCreateBundle(t, root, "intB-1")
	intB2 := mustCreateBundle(t, intB1, "intB-2")
	leaf := mustCreateBundle(t, intA2, "leaf")
	leafInterCN := mustCreateBundle(t, intA2, intA2.cert.Subject.CommonName)
	random := mustCreateBundle(t, nil, "random")

	var thousandCertBundle PEMBundle
	{
		root := mustCreateBundle(t, nil, "root")
		thousandCertBundle.CAPEM = root.pem

		cert := root
		var pems [][]byte
		for i := 0; i < 999; i++ {
			cert = mustCreateBundle(t, cert, fmt.Sprintf("int-%d", i))
			pems = append(pems, cert.pem)
		}

		for _, pem := range slices.Backward(pems) {
			thousandCertBundle.ChainPEM = joinPEM(thousandCertBundle.ChainPEM, pem)
		}
	}

	tests := map[string]struct {
		inputBundle  []byte
		expPEMBundle PEMBundle
		expErr       bool
		expErrString string
	}{
		"if two certificate chain passed in order, should return single ca and certificate": {
			inputBundle:  joinPEM(intA1.pem, root.pem),
			expPEMBundle: PEMBundle{ChainPEM: intA1.pem, CAPEM: root.pem},
			expErr:       false,
		},
		"if two certificate chain passed with leaf and intermediate, should return both certs in chain with intermediate as CA": {
			inputBundle:  joinPEM(leaf.pem, intA2.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(leaf.pem, intA2.pem), CAPEM: intA2.pem},
			expErr:       false,
		},
		"if two certificate chain passed out of order, should return single ca and certificate": {
			inputBundle:  joinPEM(root.pem, intA1.pem),
			expPEMBundle: PEMBundle{ChainPEM: intA1.pem, CAPEM: root.pem},
			expErr:       false,
		},
		"if 3 certificate chain passed out of order, should return single ca and chain in order": {
			inputBundle:  joinPEM(root.pem, intA2.pem, intA1.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(intA2.pem, intA1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"empty entries should be ignored, and return ca and certificate": {
			inputBundle:  joinPEM(root.pem, intA2.pem, []byte("\n#foo\n  \n"), intA1.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(intA2.pem, intA1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if 4 certificate chain passed in order, should return single ca and chain in order": {
			inputBundle:  joinPEM(leaf.pem, intA1.pem, intA2.pem, root.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(leaf.pem, intA2.pem, intA1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if certificate chain has two certs with the same CN, shouldn't affect output": {
			// see https://github.com/cert-manager/cert-manager/issues/4142
			inputBundle:  joinPEM(leafInterCN.pem, intA1.pem, intA2.pem, root.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(leafInterCN.pem, intA2.pem, intA1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if 4 certificate chain passed out of order, should return single ca and chain in order": {
			inputBundle:  joinPEM(root.pem, intA1.pem, leaf.pem, intA2.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(leaf.pem, intA2.pem, intA1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if 3 certificate chain but has break in the chain, should return error": {
			inputBundle:  joinPEM(root.pem, intA1.pem, leaf.pem),
			expPEMBundle: PEMBundle{},
			expErr:       true,
			expErrString: "certificate chain is malformed or broken",
		},
		"if 4 certificate chain but also random certificate, should return error": {
			inputBundle:  joinPEM(root.pem, intA1.pem, leaf.pem, intA2.pem, random.pem),
			expPEMBundle: PEMBundle{},
			expErr:       true,
			expErrString: "certificate chain is malformed or broken",
		},
		"if 6 certificate chain but some are duplicates, duplicates should be removed and return single ca with chain": {
			inputBundle:  joinPEM(intA2.pem, intA1.pem, root.pem, leaf.pem, intA1.pem, root.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(leaf.pem, intA2.pem, intA1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if 6 certificate chain in different configuration but some are duplicates, duplicates should be removed and return single ca with chain": {
			inputBundle:  joinPEM(root.pem, intA1.pem, intA2.pem, leaf.pem, root.pem, intA1.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(leaf.pem, intA2.pem, intA1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if certificate chain contains branches, then should error": {
			inputBundle:  joinPEM(root.pem, intA1.pem, intA2.pem, intB1.pem, intB2.pem),
			expPEMBundle: PEMBundle{},
			expErr:       true,
			expErrString: "certificate chain is malformed or broken",
		},
		"if certificate chain does not have a root ca, should append all intermediates to ChainPEM and use the root-most cert as CAPEM": {
			inputBundle:  joinPEM(intA1.pem, intA2.pem, leaf.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(leaf.pem, intA2.pem, intA1.pem), CAPEM: intA1.pem},
			expErr:       false,
		},
		"if only a single leaf certificate was parsed, ChainPEM should contain a single leaf certificate and CAPEM should remain empty": {
			inputBundle:  joinPEM(leaf.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(leaf.pem), CAPEM: nil},
			expErr:       false,
		},
		"if only a single intermediate certificate was parsed, ChainPEM should contain a single intermediate certificate and CAPEM should remain empty": {
			inputBundle:  joinPEM(intA1.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(intA1.pem), CAPEM: nil},
			expErr:       false,
		},
		"if only a single root certificate was parsed, ChainPEM should contain a single root certificate and CAPEM should also contain that root": {
			inputBundle:  joinPEM(root.pem),
			expPEMBundle: PEMBundle{ChainPEM: joinPEM(root.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if long chain is passed (<= 1000 certs), a result should be returned quickly": {
			inputBundle:  joinPEM(thousandCertBundle.ChainPEM, thousandCertBundle.CAPEM),
			expPEMBundle: thousandCertBundle,
			expErr:       false,
		},
		"if very long chain is passed (> 1000 certs), should error without DoS (1)": {
			inputBundle: func() []byte {
				root := mustCreateBundle(t, nil, "root")

				cert := root
				var chain []byte
				for i := 0; i < 1001; i++ {
					cert = mustCreateBundle(t, cert, fmt.Sprintf("int-%d", i))
					chain = joinPEM(chain, cert.pem)
				}

				return chain
			}(),
			expPEMBundle: PEMBundle{},
			expErr:       true,
			expErrString: "certificate chain is too long, must be less than 1000 certificates",
		},
		"if very long chain is passed (> 1000 certs), should error without DoS (2)": {
			inputBundle: func() []byte {
				root := mustCreateBundle(t, nil, "root")

				cert := root
				var chain []byte
				for i := 0; i < 10000; i++ {
					cert = mustCreateBundle(t, cert, fmt.Sprintf("int-%d", i))
					chain = joinPEM(chain, cert.pem)
				}

				return chain
			}(),
			expPEMBundle: PEMBundle{},
			expErr:       true,
			expErrString: "certificate chain is too long, must be less than 1000 certificates",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			startTime := time.Now()
			bundle, err := ParseSingleCertificateChainPEM(test.inputBundle)
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v",
					test.expErr, err)
			}

			if time.Since(startTime) > time.Second {
				t.Errorf("ParseSingleCertificateChainPEM took too long to complete, input could cause DoS")
			}

			if err != nil && err.Error() != test.expErrString {
				t.Errorf("unexpected error string, exp=%s got=%s",
					test.expErrString, err.Error())
			}

			if !reflect.DeepEqual(bundle, test.expPEMBundle) {
				t.Errorf("unexpected pem bundle, exp=%+s got=%+s",
					test.expPEMBundle, bundle)
			}
		})
	}
}
