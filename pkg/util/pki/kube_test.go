/*
Copyright 2021 The cert-manager Authors.

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

package pki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	certificatesv1 "k8s.io/api/certificates/v1"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestGenerateTemplateFromCertificateSigningRequest(t *testing.T) {
	csr, pk, err := gen.CSR(x509.RSA, gen.SetCSRCommonName("example.com"), gen.SetCSRDNSNames("example.com", "foo.example.com"))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		csr            *certificatesv1.CertificateSigningRequest
		expCertificate *x509.Certificate
		expErr         bool
	}{
		"a CSR that contains an invalid duration should return an error": {
			csr: gen.CertificateSigningRequest("",
				gen.SetCertificateSigningRequestDuration("bad-duration"),
				gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
					certificatesv1.UsageKeyEncipherment,
					certificatesv1.UsageDigitalSignature,
				}),
				gen.SetCertificateSigningRequestRequest(csr),
			),
			expCertificate: nil,
			expErr:         true,
		},
		"a CSR that contains invalid usages should return an error": {
			csr: gen.CertificateSigningRequest("",
				gen.SetCertificateSigningRequestDuration("10m"),
				gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
					certificatesv1.UsageKeyEncipherment,
					certificatesv1.KeyUsage("bad-usage"),
				}),
				gen.SetCertificateSigningRequestRequest(csr),
			),
			expCertificate: nil,
			expErr:         true,
		},
		"a CSR with isCA=true that is valid should return a valid *x509.Certificate": {
			csr: gen.CertificateSigningRequest("",
				gen.SetCertificateSigningRequestDuration("10m"),
				gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
					certificatesv1.UsageAny,
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageCRLSign,
					certificatesv1.UsageCodeSigning,
					certificatesv1.UsageContentCommitment,
				}),
				gen.SetCertificateSigningRequestIsCA(true),
				gen.SetCertificateSigningRequestRequest(csr),
			),
			expCertificate: &x509.Certificate{
				Version:               2,
				BasicConstraintsValid: true,
				SerialNumber:          nil,
				PublicKeyAlgorithm:    x509.RSA,
				PublicKey:             pk.Public(),
				IsCA:                  true,
				Subject: pkix.Name{
					CommonName: "example.com",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(10 * time.Minute),
				KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageContentCommitment,
				ExtKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageAny,
					x509.ExtKeyUsageCodeSigning,
				},
				DNSNames: []string{"example.com", "foo.example.com"},
			},
		},
		"a CSR with isCA=false that is valid should return a valid *x509.Certificate": {
			csr: gen.CertificateSigningRequest("",
				gen.SetCertificateSigningRequestDuration("10m"),
				gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
					certificatesv1.UsageAny,
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageCRLSign,
					certificatesv1.UsageCodeSigning,
					certificatesv1.UsageContentCommitment,
				}),
				gen.SetCertificateSigningRequestIsCA(false),
				gen.SetCertificateSigningRequestRequest(csr),
			),
			expCertificate: &x509.Certificate{
				Version:               2,
				BasicConstraintsValid: true,
				SerialNumber:          nil,
				PublicKeyAlgorithm:    x509.RSA,
				PublicKey:             pk.Public(),
				IsCA:                  false,
				Subject: pkix.Name{
					CommonName: "example.com",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(10 * time.Minute),
				KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageContentCommitment,
				ExtKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageAny,
					x509.ExtKeyUsageCodeSigning,
				},
				DNSNames: []string{"example.com", "foo.example.com"},
			},
		},
		"a CSR with expiration seconds that is valid should return a valid *x509.Certificate": {
			csr: gen.CertificateSigningRequest("",
				gen.SetCertificateSigningRequestExpirationSeconds(999),
				gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
					certificatesv1.UsageAny,
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageCRLSign,
					certificatesv1.UsageCodeSigning,
					certificatesv1.UsageContentCommitment,
				}),
				gen.SetCertificateSigningRequestIsCA(false),
				gen.SetCertificateSigningRequestRequest(csr),
			),
			expCertificate: &x509.Certificate{
				Version:               2,
				BasicConstraintsValid: true,
				SerialNumber:          nil,
				PublicKeyAlgorithm:    x509.RSA,
				PublicKey:             pk.Public(),
				IsCA:                  false,
				Subject: pkix.Name{
					CommonName: "example.com",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(999 * time.Second),
				KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageContentCommitment,
				ExtKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageAny,
					x509.ExtKeyUsageCodeSigning,
				},
				DNSNames: []string{"example.com", "foo.example.com"},
			},
		},
		"a CSR with expiration seconds and duration annotation should prefer the annotation duration": {
			csr: gen.CertificateSigningRequest("",
				gen.SetCertificateSigningRequestExpirationSeconds(999),
				gen.SetCertificateSigningRequestDuration("777s"),
				gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
					certificatesv1.UsageAny,
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageCRLSign,
					certificatesv1.UsageCodeSigning,
					certificatesv1.UsageContentCommitment,
				}),
				gen.SetCertificateSigningRequestIsCA(false),
				gen.SetCertificateSigningRequestRequest(csr),
			),
			expCertificate: &x509.Certificate{
				Version:               2,
				BasicConstraintsValid: true,
				SerialNumber:          nil,
				PublicKeyAlgorithm:    x509.RSA,
				PublicKey:             pk.Public(),
				IsCA:                  false,
				Subject: pkix.Name{
					CommonName: "example.com",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(777 * time.Second),
				KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageContentCommitment,
				ExtKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageAny,
					x509.ExtKeyUsageCodeSigning,
				},
				DNSNames: []string{"example.com", "foo.example.com"},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			templ, err := pki.GenerateTemplateFromCertificateSigningRequest(test.csr)
			assert.Equal(t, test.expErr, err != nil)

			if err == nil {
				deltaSec := math.Abs(test.expCertificate.NotAfter.Sub(templ.NotAfter).Seconds())
				assert.LessOrEqualf(t, deltaSec, 1., "expected a time delta lower than 1 second. Time expected='%s', got='%s'",
					test.expCertificate.NotAfter.String(),
					templ.NotAfter.String(),
				)

				// Null out field which contain values with randomised fields or are
				// not worth checking.
				test.expCertificate.NotAfter = time.Time{}
				test.expCertificate.NotBefore = time.Time{}
				templ.NotAfter = time.Time{}
				templ.NotBefore = time.Time{}
				templ.SerialNumber = nil
				templ.Subject.Names = nil

				assert.Equal(t, test.expCertificate, templ)
			}
		})
	}
}

func TestBuildKeyUsagesKube(t *testing.T) {
	tests := map[string]struct {
		usages []certificatesv1.KeyUsage
		expKU  x509.KeyUsage
		expEKU []x509.ExtKeyUsage
		expErr bool
	}{
		"no input usages should return defaults": {
			usages: nil,
			expKU:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			expErr: false,
		},
		"unknown usages should return an error": {
			usages: []certificatesv1.KeyUsage{certificatesv1.UsageAny, certificatesv1.KeyUsage("unknown-")},
			expKU:  -1,
			expErr: true,
		},
		"multiple valid usages should return those usages": {
			usages: []certificatesv1.KeyUsage{
				certificatesv1.UsageAny,
				certificatesv1.UsageDigitalSignature,
				certificatesv1.UsageCRLSign,
				certificatesv1.UsageCodeSigning,
				certificatesv1.UsageContentCommitment,
			},
			expKU: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageContentCommitment,
			expEKU: []x509.ExtKeyUsage{
				x509.ExtKeyUsageAny,
				x509.ExtKeyUsageCodeSigning,
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ku, eku, err := pki.BuildKeyUsagesKube(test.usages)
			assert.Equal(t, test.expKU, ku)
			assert.Equal(t, test.expEKU, eku)
			assert.Equal(t, test.expErr, err != nil)
		})
	}
}
