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

package certificate

import (
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestFormatStringSlice(t *testing.T) {
	tests := map[string]struct {
		slice     []string
		expOutput string
	}{
		// Newlines are part of the expected output
		"Empty slice returns empty string": {
			slice:     []string{},
			expOutput: ``,
		},
		"Slice with one element returns string with one line": {
			slice: []string{"hello"},
			expOutput: `- hello
`,
		},
		"Slice with multiple elements returns string with multiple lines": {
			slice: []string{"hello", "World", "another line"},
			expOutput: `- hello
- World
- another line
`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actualOutput := formatStringSlice(test.slice); actualOutput != test.expOutput {
				t.Errorf("Unexpected output; expected: \n%s\nactual: \n%s", test.expOutput, actualOutput)
			}
		})
	}
}

func TestCRInfoString(t *testing.T) {
	tests := map[string]struct {
		cr        *cmapi.CertificateRequest
		err       error
		expOutput string
	}{
		// Newlines are part of the expected output
		"Nil pointer output correct": {
			cr:  nil,
			err: errors.New("No CertificateRequest found for this Certificate\n"),
			expOutput: `No CertificateRequest found for this Certificate
`,
		},
		"CR with no condition output correct": {
			cr: &cmapi.CertificateRequest{Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{}}},
			expOutput: `CertificateRequest:
  Name:
  Namespace:
  Conditions:
    No Conditions set
  Events:  <none>
`,
		},
		"CR with conditions output correct": {
			cr: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionTrue, Message: "example"},
					}}},
			expOutput: `CertificateRequest:
  Name:
  Namespace:
  Conditions:
    Ready: True, Reason: , Message: example
  Events:  <none>
`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actualOutput := (&CertificateStatus{}).withCR(test.cr, nil, test.err).CRStatus.String()
			if strings.ReplaceAll(actualOutput, " \n", "\n") != strings.ReplaceAll(test.expOutput, " \n", "\n") {
				t.Errorf("Unexpected output; expected: \n%s\nactual: \n%s", test.expOutput, actualOutput)
			}
		})
	}
}

func TestKeyUsageToString(t *testing.T) {
	tests := map[string]struct {
		usage     x509.KeyUsage
		expOutput string
	}{
		"no key usage set": {
			usage:     x509.KeyUsage(0),
			expOutput: "",
		},
		"key usage Digital Signature": {
			usage:     x509.KeyUsageDigitalSignature,
			expOutput: "Digital Signature",
		},
		"key usage Digital Signature and Data Encipherment": {
			usage:     x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			expOutput: "Digital Signature, Data Encipherment",
		},
		"key usage with three usages is ordered": {
			usage:     x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageContentCommitment,
			expOutput: "Digital Signature, Content Commitment, Data Encipherment",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actualOutput := keyUsageToString(test.usage); actualOutput != test.expOutput {
				t.Errorf("Unexpected output; expected: \n%s\nactual: \n%s", test.expOutput, actualOutput)
			}
		})
	}
}

func TestExtKeyUsageToString(t *testing.T) {
	tests := map[string]struct {
		extUsage       []x509.ExtKeyUsage
		expOutput      string
		expError       bool
		expErrorOutput string
	}{
		"no extended key usage": {
			extUsage:  []x509.ExtKeyUsage{},
			expOutput: "",
		},
		"extended key usage Any": {
			extUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			expOutput: "Any",
		},
		"multiple extended key usages": {
			extUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
			expOutput: "Client Authentication, Email Protection",
		},
		"undefined extended key usage": {
			extUsage:       []x509.ExtKeyUsage{x509.ExtKeyUsage(42)},
			expOutput:      "",
			expError:       true,
			expErrorOutput: "error when converting Extended Usages to string: encountered unknown Extended Usage with code 42",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actualOutput, err := extKeyUsageToString(test.extUsage)
			if err != nil {
				if !test.expError || test.expErrorOutput != err.Error() {
					t.Errorf("got unexpected error. This test expects an error: %t. expected error: %q, actual error: %q",
						test.expError, test.expErrorOutput, err.Error())
				}
			} else if test.expError {
				t.Errorf("expects error: %q, but did not get any", test.expErrorOutput)
			}
			if actualOutput != test.expOutput {
				t.Errorf("Unexpected output; expected: \n%s\nactual: \n%s", test.expOutput, actualOutput)
			}
		})
	}
}

func TestStatusFromResources(t *testing.T) {
	timestamp, err := time.Parse(time.RFC3339, "2020-09-16T09:26:18Z")
	if err != nil {
		t.Fatal(err)
	}

	tlsCrt := []byte(`-----BEGIN CERTIFICATE-----
MIICyTCCAbGgAwIBAgIRAOL4jtyULBSEYyGdqQn9YzowDQYJKoZIhvcNAQELBQAw
DzENMAsGA1UEAxMEdGVzdDAeFw0yMDA3MzAxNjExNDNaFw0yMDEwMjgxNjExNDNa
MA8xDTALBgNVBAMTBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDdfNmjh5ag7f6U1hj1OAx/dEN9kQzPsSlBMXGb/Ho4k5iegrFd6w8JkYdCthFv
lfg3bIhw5tCKaw1o57HnWKBKKGt7XpeIu1mEcv8pveMIPO7TZ4+oElgX880NfJmL
DkjEcctEo/+FurudO1aEbNfbNWpzudYKj7gGtYshBytqaYt4/APqWARJBFCYVVys
wexZ0fLi5cBD8H1bQ1Ec3OCr5Mrq9thAGkj+rVlgYR0AZVGa9+SCOj27t6YCmyzR
AJSEQ35v58Zfxp5tNyYd6wcAswJ9YipnUXvwahF95PNlRmMhp3Eo15m9FxehcVXU
BOfxykMwZN7onMhuHiiwiB+NAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIFoDAMBgNV
HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQALrnldWjTBTvV5WKapUHUG0rhA
vp2Cf+5FsPw8vKScXp4L+wKGdPOjhHz6NOiw5wu8A0HxlVUFawRpagkjFkeTL78O
9ghBHLiqn9xNPIKC6ID3WpnN5terwQxQeO/M54sVMslUWCcZm9Pu4Eb//2e6wEdu
eMmpfeISQmCsBC1CTmpxUjeUg5DEQ0X1TQykXq+bG2iso6RYPxZTFTHJFzXiDYEc
/X7H+bOmpo/dMrXapwfvp2gD+BEq96iVpf/DBzGYNs/657LAHJ4YtxtAZCa1CK9G
MA6koCR/K23HZfML8vT6lcHvQJp9XXaHRIe9NX/M/2f6VpfO7JjKWLou5k5a
-----END CERTIFICATE-----`)

	serialNum, _ := new(big.Int).SetString("301696114246524167282555582613204853562", 10)
	ns := "ns1"
	dummyEventList := &corev1.EventList{
		Items: []corev1.Event{{
			Type:    "type",
			Reason:  "reason",
			Message: "message",
		}},
	}

	tests := map[string]struct {
		inputData *Data
		expOutput *CertificateStatus
	}{
		"Correct information extracted from Certificate resource": {
			inputData: &Data{
				Certificate: gen.Certificate("test-crt",
					gen.SetCertificateNamespace(ns),
					gen.SetCertificateNotAfter(metav1.Time{Time: timestamp}),
					gen.SetCertificateNotBefore(metav1.Time{Time: timestamp}),
					gen.SetCertificateRenewalTime(metav1.Time{Time: timestamp}),
					gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady,
						Status: cmmeta.ConditionTrue, Message: "Certificate is up to date and has not expired"}),
					gen.SetCertificateDNSNames("example.com"),
				),
				CrtEvents: dummyEventList,
			},
			expOutput: &CertificateStatus{
				Name:         "test-crt",
				Namespace:    ns,
				CreationTime: metav1.Time{},
				Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady,
					Status: cmmeta.ConditionTrue, Message: "Certificate is up to date and has not expired"}},
				DNSNames:    []string{"example.com"},
				Events:      dummyEventList,
				NotBefore:   &metav1.Time{Time: timestamp},
				NotAfter:    &metav1.Time{Time: timestamp},
				RenewalTime: &metav1.Time{Time: timestamp},
			},
		},
		"Issuer correctly with Kind Issuer": {
			inputData: &Data{
				Certificate: gen.Certificate("test-crt",
					gen.SetCertificateNamespace(ns)),
				Issuer:       gen.Issuer("test-issuer"),
				IssuerKind:   "Issuer",
				IssuerError:  nil,
				IssuerEvents: dummyEventList,
			},
			expOutput: &CertificateStatus{
				Name:         "test-crt",
				Namespace:    ns,
				CreationTime: metav1.Time{},
				IssuerStatus: &IssuerStatus{
					Name:   "test-issuer",
					Kind:   "Issuer",
					Events: dummyEventList,
				},
			},
		},
		"Issuer correctly with Kind ClusterIssuer": {
			inputData: &Data{
				Certificate: gen.Certificate("test-crt",
					gen.SetCertificateNamespace(ns)),
				Issuer:       gen.Issuer("test-clusterissuer"),
				IssuerKind:   "ClusterIssuer",
				IssuerError:  nil,
				IssuerEvents: dummyEventList,
			},
			expOutput: &CertificateStatus{
				Name:         "test-crt",
				Namespace:    ns,
				CreationTime: metav1.Time{},
				IssuerStatus: &IssuerStatus{
					Name:   "test-clusterissuer",
					Kind:   "ClusterIssuer",
					Events: dummyEventList,
				},
			},
		},
		"Correct information extracted from Secret resource": {
			inputData: &Data{
				Certificate: gen.Certificate("test-crt",
					gen.SetCertificateNamespace(ns)),
				Secret: gen.Secret("existing-tls-secret",
					gen.SetSecretNamespace(ns),
					gen.SetSecretData(map[string][]byte{"tls.crt": tlsCrt})),
				SecretError:  nil,
				SecretEvents: dummyEventList,
			},
			expOutput: &CertificateStatus{
				Name:         "test-crt",
				Namespace:    ns,
				CreationTime: metav1.Time{},
				SecretStatus: &SecretStatus{
					Error:              nil,
					Name:               "existing-tls-secret",
					IssuerCountry:      nil,
					IssuerOrganisation: nil,
					IssuerCommonName:   "test",
					KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
					ExtKeyUsage:        nil,
					PublicKeyAlgorithm: x509.RSA,
					SignatureAlgorithm: x509.SHA256WithRSA,
					SubjectKeyId:       nil,
					AuthorityKeyId:     nil,
					SerialNumber:       serialNum,
					Events:             dummyEventList,
				},
			},
		},
		"Correct information extracted from CR resource": {
			inputData: &Data{
				Certificate: gen.Certificate("test-crt",
					gen.SetCertificateNamespace(ns)),
				Req: gen.CertificateRequest("test-req",
					gen.SetCertificateRequestNamespace(ns),
					gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: "Pending", Message: "Waiting on certificate issuance from order default/example-order: \"pending\""})),
				ReqError:  nil,
				ReqEvents: dummyEventList,
			},
			expOutput: &CertificateStatus{
				Name:         "test-crt",
				Namespace:    ns,
				CreationTime: metav1.Time{},
				CRStatus: &CRStatus{
					Error:      nil,
					Name:       "test-req",
					Namespace:  ns,
					Conditions: []cmapi.CertificateRequestCondition{{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: "Pending", Message: "Waiting on certificate issuance from order default/example-order: \"pending\""}},
					Events:     dummyEventList,
				},
			},
		},
		"Correct information extracted from Order resource": {
			inputData: &Data{
				Certificate: gen.Certificate("test-crt",
					gen.SetCertificateNamespace(ns)),
				Order: &cmacme.Order{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "example-order", Namespace: ns},
					Spec:       cmacme.OrderSpec{Request: []byte("dummyCSR"), DNSNames: []string{"www.example.com"}},
					Status:     cmacme.OrderStatus{},
				},
				OrderError: nil,
			},
			expOutput: &CertificateStatus{
				Name:         "test-crt",
				Namespace:    ns,
				CreationTime: metav1.Time{},
				OrderStatus: &OrderStatus{
					Error:          nil,
					Name:           "example-order",
					State:          "",
					Reason:         "",
					Authorizations: nil,
					FailureTime:    nil,
				},
			},
		},
		"Correct information extracted from Challenge resources": {
			inputData: &Data{
				Certificate: gen.Certificate("test-crt",
					gen.SetCertificateNamespace(ns)),
				Challenges: []*cmacme.Challenge{
					{
						TypeMeta:   metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{Name: "test-challenge1", Namespace: ns},
						Spec: cmacme.ChallengeSpec{
							Type:  "HTTP-01",
							Token: "token",
							Key:   "key",
						},
						Status: cmacme.ChallengeStatus{
							Processing: false,
							Presented:  false,
							Reason:     "reason",
							State:      "state",
						},
					},
					{
						TypeMeta:   metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{Name: "test-challenge2", Namespace: ns},
						Spec: cmacme.ChallengeSpec{
							Type:  "HTTP-01",
							Token: "token",
							Key:   "key",
						},
						Status: cmacme.ChallengeStatus{
							Processing: false,
							Presented:  false,
							Reason:     "reason",
							State:      "state",
						},
					},
				},
				ChallengeErr: nil,
			},
			expOutput: &CertificateStatus{
				Name:         "test-crt",
				Namespace:    ns,
				CreationTime: metav1.Time{},
				ChallengeStatusList: &ChallengeStatusList{
					ChallengeStatuses: []*ChallengeStatus{
						{
							Name:       "test-challenge1",
							Type:       "HTTP-01",
							Token:      "token",
							Key:        "key",
							State:      "state",
							Reason:     "reason",
							Processing: false,
							Presented:  false,
						},
						{
							Name:       "test-challenge2",
							Type:       "HTTP-01",
							Token:      "token",
							Key:        "key",
							State:      "state",
							Reason:     "reason",
							Processing: false,
							Presented:  false,
						},
					},
				},
			},
		},
		"When error, ignore rest of the info about the resource": {
			inputData: &Data{
				Certificate: gen.Certificate("test-crt",
					gen.SetCertificateNamespace(ns)),
				CrtEvents:    nil,
				Issuer:       gen.Issuer("test-issuer"),
				IssuerKind:   "",
				IssuerError:  errors.New("dummy error"),
				IssuerEvents: dummyEventList,
				Secret:       gen.Secret("test-secret"),
				SecretError:  errors.New("dummy error"),
				SecretEvents: dummyEventList,
				Req:          gen.CertificateRequest("test-req"),
				ReqError:     errors.New("dummy error"),
				ReqEvents:    dummyEventList,
				Order: &cmacme.Order{
					ObjectMeta: metav1.ObjectMeta{Name: "test-order"},
				},
				OrderError:   errors.New("dummy error"),
				Challenges:   []*cmacme.Challenge{{ObjectMeta: metav1.ObjectMeta{Name: "test-challenge"}}},
				ChallengeErr: errors.New("dummy error"),
			},
			expOutput: &CertificateStatus{
				Name:                "test-crt",
				Namespace:           ns,
				CreationTime:        metav1.Time{},
				IssuerStatus:        &IssuerStatus{Error: errors.New("dummy error")},
				SecretStatus:        &SecretStatus{Error: errors.New("dummy error")},
				CRStatus:            &CRStatus{Error: errors.New("dummy error")},
				OrderStatus:         &OrderStatus{Error: errors.New("dummy error")},
				ChallengeStatusList: &ChallengeStatusList{Error: errors.New("dummy error")},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := StatusFromResources(test.inputData)
			assert.Equal(t, test.expOutput, got)
		})
	}
}
