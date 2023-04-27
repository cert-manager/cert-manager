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

package secret

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	testCert            string
	testCertSerial      string
	testCertFingerprint string
	testNotBefore       string
	testNotAfter        string
)

func init() {
	caKey, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		panic(err)
	}
	caCertificateTemplate := gen.Certificate(
		"ca",
		gen.SetCertificateCommonName("testing-ca"),
		gen.SetCertificateIsCA(true),
		gen.SetCertificateKeyAlgorithm(v1.ECDSAKeyAlgorithm),
		gen.SetCertificateKeySize(256),
		gen.SetCertificateKeyUsages(
			v1.UsageDigitalSignature,
			v1.UsageKeyEncipherment,
			v1.UsageCertSign,
		),
		gen.SetCertificateNotBefore(metav1.Time{Time: time.Now().Add(-time.Hour)}),
		gen.SetCertificateNotAfter(metav1.Time{Time: time.Now().Add(time.Hour)}),
	)
	caCertificateTemplate.Spec.Subject = &v1.X509Subject{
		Organizations:       []string{"Internet Widgets, Inc."},
		Countries:           []string{"US"},
		OrganizationalUnits: []string{"WWW"},
		Localities:          []string{"San Francisco"},
		Provinces:           []string{"California"},
	}
	caX509Cert, err := pki.GenerateTemplate(caCertificateTemplate)
	if err != nil {
		panic(err)
	}
	_, caCert, err := pki.SignCertificate(caX509Cert, caX509Cert, caKey.Public(), caKey)
	if err != nil {
		panic(err)
	}

	testCertKey, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		panic(err)
	}
	testCertTemplate := gen.Certificate(
		"testing-cert",
		gen.SetCertificateDNSNames("cert-manager.test"),
		gen.SetCertificateIPs("10.0.0.1"),
		gen.SetCertificateURIs("spiffe://cert-manager.test"),
		gen.SetCertificateEmails("test@cert-manager.io"),
		gen.SetCertificateIsCA(true),
		gen.SetCertificateKeyAlgorithm(v1.ECDSAKeyAlgorithm),
		gen.SetCertificateIsCA(false),
		gen.SetCertificateKeySize(256),
		gen.SetCertificateKeyUsages(
			v1.UsageDigitalSignature,
			v1.UsageKeyEncipherment,
			v1.UsageServerAuth,
			v1.UsageClientAuth,
		),
		gen.SetCertificateNotBefore(metav1.Time{Time: time.Now().Add(-30 * time.Minute)}),
		gen.SetCertificateNotAfter(metav1.Time{Time: time.Now().Add(30 * time.Minute)}),
	)
	testCertTemplate.Spec.Subject = &v1.X509Subject{
		Organizations:       []string{"cncf"},
		Countries:           []string{"GB"},
		OrganizationalUnits: []string{"cert-manager"},
	}
	testX509Cert, err := pki.GenerateTemplate(testCertTemplate)
	if err != nil {
		panic(err)
	}

	testCertPEM, testCertGo, err := pki.SignCertificate(testX509Cert, caCert, testCertKey.Public(), caKey)
	if err != nil {
		panic(err)
	}

	testCert = string(testCertPEM)
	testCertSerial = testCertGo.SerialNumber.String()
	testCertFingerprint = fingerprintCert(testCertGo)
	testNotBefore = testCertGo.NotBefore.Format(time.RFC1123)
	testNotAfter = testCertGo.NotAfter.Format(time.RFC1123)
}

func MustParseCertificate(t *testing.T, certData string) *x509.Certificate {
	x509Cert, err := pki.DecodeX509CertificateBytes([]byte(certData))
	if err != nil {
		t.Fatalf("error when parsing crt: %v", err)
	}

	return x509Cert
}

func Test_describeCRL(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Print cert without CRL",
			cert: MustParseCertificate(t, testCert),
			want: "No CRL endpoints set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeCRL(tt.cert); got != tt.want {
				t.Errorf("describeCRL() = %v, want %v", makeInvisibleVisible(got), makeInvisibleVisible(tt.want))
			}
		})
	}
}

func Test_describeCertificate(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Describe test certificate",
			cert: MustParseCertificate(t, testCert),
			want: `Certificate:
	Signing Algorithm:	ECDSA-SHA256
	Public Key Algorithm: 	ECDSA
	Serial Number:	` + testCertSerial + `
	Fingerprints: 	` + testCertFingerprint + `
	Is a CA certificate: false
	CRL:	<none>
	OCSP:	<none>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeCertificate(tt.cert); got != tt.want {
				t.Errorf("describeCertificate() = %v, want %v", makeInvisibleVisible(got), makeInvisibleVisible(tt.want))
			}
		})
	}
}

func Test_describeDebugging(t *testing.T) {
	type args struct {
		cert          *x509.Certificate
		intermediates [][]byte
		ca            []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Debug test cert without trusting CA",
			args: args{
				cert:          MustParseCertificate(t, testCert),
				intermediates: nil,
				ca:            nil,
			},
			want: `Debugging:
	Trusted by this computer:	no: x509: certificate signed by unknown authority
	CRL Status:	No CRL endpoints set
	OCSP Status:	Cannot check OCSP, does not have a CA or intermediate certificate provided`,
		},
		// TODO: add fake clock and test with trusting CA
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeDebugging(tt.args.cert, tt.args.intermediates, tt.args.ca); got != tt.want {
				t.Errorf("describeDebugging() = %v, want %v", makeInvisibleVisible(got), makeInvisibleVisible(tt.want))
			}
		})
	}
}

func Test_describeIssuedBy(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Describe test certificate",
			cert: MustParseCertificate(t, testCert),
			want: `Issued By:
	Common Name:	testing-ca
	Organization:	testing-ca
	OrganizationalUnit:	Internet Widgets, Inc.
	Country:	US`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeIssuedBy(tt.cert); got != tt.want {
				t.Errorf("describeIssuedBy() = %v, want %v", makeInvisibleVisible(got), makeInvisibleVisible(tt.want))
			}
		})
	}
}

func Test_describeIssuedFor(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Describe test cert",
			cert: MustParseCertificate(t, testCert),
			want: `Issued For:
	Common Name:	<none>
	Organization:	<none>
	OrganizationalUnit:	cncf
	Country:	GB`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeIssuedFor(tt.cert); got != tt.want {
				t.Errorf("describeIssuedFor() = %v, want %v", makeInvisibleVisible(got), makeInvisibleVisible(tt.want))
			}
		})
	}
}

func Test_describeOCSP(t *testing.T) {
	type args struct {
		cert          *x509.Certificate
		intermediates [][]byte
		ca            []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Describe cert with no OCSP",
			args: args{
				cert: MustParseCertificate(t, testCert),
			},
			want: "Cannot check OCSP, does not have a CA or intermediate certificate provided",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeOCSP(tt.args.cert, tt.args.intermediates, tt.args.ca); got != tt.want {
				t.Errorf("describeOCSP() = %v, want %v", makeInvisibleVisible(got), makeInvisibleVisible(tt.want))
			}
		})
	}
}

func Test_describeTrusted(t *testing.T) {
	// set clock to when our test cert was trusted
	t1, _ := time.Parse("Thu, 27 Nov 2020 10:00:00 UTC", time.RFC1123)
	clock = fakeclock.NewFakeClock(t1)
	type args struct {
		cert          *x509.Certificate
		intermediates [][]byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Describe test certificate",
			args: args{
				cert:          MustParseCertificate(t, testCert),
				intermediates: nil,
			},
			want: "no: x509: certificate signed by unknown authority",
		},
		{
			name: "Describe test certificate with adding it to the trust store",
			args: args{
				cert:          MustParseCertificate(t, testCert),
				intermediates: [][]byte{[]byte(testCert)},
			},
			want: "yes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeTrusted(tt.args.cert, tt.args.intermediates); got != tt.want {
				t.Errorf("describeTrusted() = %v, want %v", makeInvisibleVisible(got), makeInvisibleVisible(tt.want))
			}
		})
	}
}

func Test_describeValidFor(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Describe test certificate",
			cert: MustParseCertificate(t, testCert),
			want: `Valid for:
	DNS Names: 
		- cert-manager.test
	URIs: 
		- spiffe://cert-manager.test
	IP Addresses: 
		- 10.0.0.1
	Email Addresses: 
		- test@cert-manager.io
	Usages: 
		- digital signature
		- key encipherment
		- server auth
		- client auth`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeValidFor(tt.cert); got != tt.want {
				t.Errorf("describeValidFor() = %v, want %v", makeInvisibleVisible(got), makeInvisibleVisible(tt.want))
			}
		})
	}
}

func Test_describeValidityPeriod(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Describe test certificate",
			cert: MustParseCertificate(t, testCert),
			want: `Validity period:
	Not Before: ` + testNotBefore + `
	Not After: ` + testNotAfter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeValidityPeriod(tt.cert); got != tt.want {
				t.Errorf("describeValidityPeriod() = %v, want %v", makeInvisibleVisible(got), makeInvisibleVisible(tt.want))
			}
		})
	}
}

func makeInvisibleVisible(in string) string {
	in = strings.Replace(in, "\n", "\\n\n", -1)
	in = strings.Replace(in, "\t", "\\t", -1)

	return in
}
