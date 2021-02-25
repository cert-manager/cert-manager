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

	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const testCert = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIQZcMA0zmHAF59XPwyJ5isYTANBgkqhkiG9w0BAQsFADBF
MQswCQYDVQQGEwJCRTENMAsGA1UEChMEY25jZjEVMBMGA1UECxMMY2VydC1tYW5h
Z2VyMRAwDgYDVQQDEwd0ZXN0LWNhMB4XDTIwMTEyNjEwMTU1NVoXDTIxMDIyNDEw
MTU1NVowRzELMAkGA1UEBhMCQkUxDTALBgNVBAoTBGNuY2YxFTATBgNVBAsTDGNl
cnQtbWFuYWdlcjESMBAGA1UEAxMJVGVzdCBDZXJ0MFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEyyZL+5lqdsHGAu/LskCzH7hxuHNcDL94P7hejBDdWo8qfYgJCv2P
yuRG2gCWeUbJdxQxwejjTDQGgsREZYU1YqOBvTCBujAOBgNVHQ8BAf8EBAMCBaAw
IwYDVR0lBBwwGgYEVR0lAAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAUWfIOb7hiqgkyiKGsljHW4kVJeEMwVAYDVR0RBE0wS4IR
Y2VydC1tYW5hZ2VyLnRlc3SBFHRlc3RAY2VydC1tYW5hZ2VyLmlvhwQKAAABhhpz
cGlmZmU6Ly9jZXJ0LW1hbmFnZXIudGVzdDANBgkqhkiG9w0BAQsFAAOCAQEAscxM
8Kkaq2KePyiMyboyYLnaWdS+V5XIB15gsseXN2wcuWyX74WsKRfuwD2KrDenaaOc
ziMelxT3HlEOT/efmZlwP2CvTYvOKNEoLnH4RnehpVSPcrkP4mVCJ3Rnk1g5XZO3
OJ8wRLEjZxDOTBllEE6LH4BTNJZX8Dt1wUwaJdMwZvYOWM0570Pv1O59qRggV/we
EpFEF9AeUM7wopJCgwNgN8Eh28RVVjL78ZlTEw3pQrPqWUnz9uyx7guumP7D+Y0D
smSH8yw3PNftw5kD2ORK3EnkRtZcZIl0O/C6RiNLxBT/GR1opQpQGWlPBjtVOZlq
JuuLwYEHo8JSNLGsUQ==
-----END CERTIFICATE-----
`

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
	Signing Algorithm:	SHA256-RSA
	Public Key Algorithm: 	ECDSA
	Serial Number:	135264542196636937349115151139823201377
	Fingerprints: 	A9:4D:28:6F:1E:78:4A:72:C7:38:01:7C:31:CC:42:09:C7:46:9C:6A:26:C5:71:1A:F1:35:11:6E:BA:C3:BA:5A
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
	Common Name:	test-ca
	Organization:	test-ca
	OrganizationalUnit:	cncf
	Country:	BE`,
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
	Common Name:	Test Cert
	Organization:	Test Cert
	OrganizationalUnit:	cncf
	Country:	BE`,
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
		- any
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
	Not Before: Thu, 26 Nov 2020 10:15:55 UTC
	Not After: Wed, 24 Feb 2021 10:15:55 UTC`,
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
