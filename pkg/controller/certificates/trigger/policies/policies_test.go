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

package policies

import (
	"encoding/pem"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// Runs a full set of tests against the 'policy chain' once it is composed
// together.
// These tests account for the ordering of the policy chain, and are in place
// to ensure we do not break behaviour when introducing a new policy or
// modifying existing code.
func TestDefaultPolicyChain(t *testing.T) {
	clock := &fakeclock.FakeClock{}
	staticFixedPrivateKey := generatePEMPrivateKey(t)
	tests := map[string]struct {
		// policy inputs
		certificate *cmapi.Certificate
		request     *cmapi.CertificateRequest
		secret      *corev1.Secret

		// expected outputs
		reason, message string
		reissue         bool
	}{
		"trigger issuance if Secret is missing": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			reason:      "DoesNotExist",
			message:     "Issuing certificate as Secret does not exist",
			reissue:     true,
		},
		"trigger issuance as Secret does not contain any data": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret:      &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"}},
			reason:      "MissingData",
			message:     "Issuing certificate as Secret does not contain any data",
			reissue:     true,
		},
		"trigger issuance as Secret is missing private key": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{corev1.TLSCertKey: []byte("test")},
			},
			reason:  "MissingData",
			message: "Issuing certificate as Secret does not contain a private key",
			reissue: true,
		},
		"trigger issuance as Secret is missing certificate": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{corev1.TLSPrivateKeyKey: []byte("test")},
			},
			reason:  "MissingData",
			message: "Issuing certificate as Secret does not contain a certificate",
			reissue: true,
		},
		"trigger issuance as Secret contains corrupt private key and certificate data": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: []byte("test"),
					corev1.TLSCertKey:       []byte("test"),
				},
			},
			reason:  "InvalidKeyPair",
			message: "Issuing certificate as Secret contains an invalid key-pair: tls: failed to find any PEM data in certificate input",
			reissue: true,
		},
		"trigger issuance as Secret contains corrupt certificate data": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: generatePEMPrivateKey(t),
					corev1.TLSCertKey:       []byte("test"),
				},
			},
			reason:  "InvalidKeyPair",
			message: "Issuing certificate as Secret contains an invalid key-pair: tls: failed to find any PEM data in certificate input",
			reissue: true,
		},
		"trigger issuance as Secret contains corrupt private key data": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: []byte("invalid"),
					corev1.TLSCertKey: selfSignCertificate(t, generatePEMPrivateKey(t),
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  "InvalidKeyPair",
			message: "Issuing certificate as Secret contains an invalid key-pair: tls: failed to find any PEM data in key input",
			reissue: true,
		},
		"trigger issuance as Secret contains a non-matching key-pair": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: generatePEMPrivateKey(t),
					corev1.TLSCertKey: selfSignCertificate(t, generatePEMPrivateKey(t),
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  "InvalidKeyPair",
			message: "Issuing certificate as Secret contains an invalid key-pair: tls: private key does not match public key",
			reissue: true,
		},
		"trigger issuance as Secret has old/incorrect 'issuer name' annotation": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				SecretName: "something",
				IssuerRef: cmmeta.ObjectReference{
					Name: "testissuer",
				},
			}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "oldissuer",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificate(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  "IncorrectIssuer",
			message: "Issuing certificate as Secret was previously issued by Issuer.cert-manager.io/oldissuer",
			reissue: true,
		},
		"trigger issuance as Secret has old/incorrect 'issuer kind' annotation": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				SecretName: "something",
				IssuerRef: cmmeta.ObjectReference{
					Name: "testissuer",
					Kind: "NewIssuerKind",
				},
			}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "testissuer",
						cmapi.IssuerKindAnnotationKey: "OldIssuerKind",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificate(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  "IncorrectIssuer",
			message: "Issuing certificate as Secret was previously issued by OldIssuerKind.cert-manager.io/testissuer",
			reissue: true,
		},
		"trigger issuance as Secret has old/incorrect 'issuer group' annotation": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				SecretName: "something",
				IssuerRef: cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "old.example.com",
				},
			}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "new.example.com",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificate(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  "IncorrectIssuer",
			message: "Issuing certificate as Secret was previously issued by IssuerKind.new.example.com/testissuer",
			reissue: true,
		},
		// we only have a basic test here for this as unit tests for the
		// `certificates.RequestMatchesSpec` function cover all other cases.
		"trigger issuance when CertificateRequest does not match certificate spec": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "new.example.com",
				IssuerRef: cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				},
			}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificate(t, staticFixedPrivateKey,
						// It does not matter what certificate data is stored in the Secret
						// as the CertificateRequest will be used to determine whether a
						// re-issuance is required.
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "does-not-matter.example.com"}},
					),
				},
			},
			request: &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{
				IssuerRef: cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				},
				Request: generatePEMCertificateRequest(t, staticFixedPrivateKey, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					CommonName: "old.example.com",
				}}),
			}},
			reason:  "RequestChanged",
			message: "Fields on existing CertificateRequest resource not up to date: [spec.commonName]",
			reissue: true,
		},
		"do nothing if CertificateRequest matches spec": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "example.com",
				IssuerRef: cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				},
			}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificate(t, staticFixedPrivateKey,
						// It does not matter what certificate data is stored in the Secret
						// as the CertificateRequest will be used to determine whether a
						// re-issuance is required.
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "does-not-matter.example.com"}},
					),
				},
			},
			request: &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{
				IssuerRef: cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				},
				Request: generatePEMCertificateRequest(t, staticFixedPrivateKey, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
				}}),
			}},
		},
		"compare signed x509 certificate in Secret with spec if CertificateRequest does not exist": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "new.example.com",
				IssuerRef: cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				},
			}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificate(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "old.example.com"}},
					),
				},
			},
			reason:  "SecretMismatch",
			message: "Existing issued Secret is not up to date for spec: [spec.commonName]",
			reissue: true,
		},
		"do nothing if signed x509 certificate in Secret matches spec (when request does not exist)": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "example.com",
				IssuerRef: cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				},
			}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificate(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
		},
		"trigger renewal if renewalTime is right now": {
			certificate: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					RenewBefore: &metav1.Duration{Duration: time.Minute * 5},
				},
				Status: cmapi.CertificateStatus{
					RenewalTime: &metav1.Time{Time: clock.Now()},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificateWithNotBeforeAfter(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
						clock.Now().Add(time.Minute*-30),
						// expires in 1 minute time
						clock.Now().Add(time.Minute*1),
					),
				},
			},
			reason:  "Renewing",
			message: "Renewing certificate as renewal was scheduled at 0001-01-01 00:00:00 +0000 UTC",
			reissue: true,
		},
		"trigger renewal if renewalTime is in the past": {
			certificate: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					RenewBefore: &metav1.Duration{Duration: time.Minute * 5},
				},
				Status: cmapi.CertificateStatus{
					RenewalTime: &metav1.Time{Time: clock.Now().Add(-1 * time.Minute)},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificateWithNotBeforeAfter(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
						clock.Now().Add(time.Minute*-30),
						// expires in 1 minute time
						clock.Now().Add(time.Minute*1),
					),
				},
			},
			reason:  "Renewing",
			message: "Renewing certificate as renewal was scheduled at 0000-12-31 23:59:00 +0000 UTC",
			reissue: true,
		},
		"does not trigger renewal if renewal time is in 1 minute": {
			certificate: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					RenewBefore: &metav1.Duration{Duration: time.Minute * 1},
				},
				Status: cmapi.CertificateStatus{
					RenewalTime: &metav1.Time{Time: clock.Now().Add(time.Minute)},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: selfSignCertificateWithNotBeforeAfter(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
						clock.Now().Add(time.Minute*-30),
						// expires in 5 minutes time
						clock.Now().Add(time.Minute*5),
					),
				},
			},
		},
	}
	policyChain := NewTriggerPolicyChain(clock)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			reason, message, reissue := policyChain.Evaluate(Input{
				Certificate:            test.certificate,
				CurrentRevisionRequest: test.request,
				Secret:                 test.secret,
			})

			if test.reason != reason {
				t.Errorf("unexpected 'reason' exp=%s, got=%s", test.reason, reason)
			}
			if test.message != message {
				t.Errorf("unexpected 'message' exp=%s, got=%s", test.message, message)
			}
			if test.reissue != reissue {
				t.Errorf("unexpected 'reissue' exp=%v, got=%v", test.reissue, reissue)
			}
		})
	}
}

func generatePEMPrivateKey(t *testing.T) []byte {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pkData, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	if err != nil {
		t.Fatal(err)
	}
	return pkData
}

func selfSignCertificateWithNotBeforeAfter(t *testing.T, pkData []byte, spec *cmapi.Certificate, notBefore, notAfter time.Time) []byte {
	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		t.Fatal(err)
	}

	template, err := pki.GenerateTemplate(spec)
	if err != nil {
		t.Fatal(err)
	}

	if notBefore != (time.Time{}) {
		template.NotBefore = notBefore
	}
	if notAfter != (time.Time{}) {
		template.NotAfter = notAfter
	}

	certData, _, err := pki.SignCertificate(template, template, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}

	return certData
}

func selfSignCertificate(t *testing.T, pkData []byte, spec *cmapi.Certificate) []byte {
	return selfSignCertificateWithNotBeforeAfter(t, pkData, spec, time.Time{}, time.Time{})
}

func generatePEMCertificateRequest(t *testing.T, pkData []byte, cert *cmapi.Certificate) []byte {
	csr, err := pki.GenerateCSR(cert)
	if err != nil {
		t.Fatal(err)
	}

	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		t.Fatal(err)
	}

	csrDER, err := pki.EncodeCSR(csr, pk)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	})

	return csrPEM
}
