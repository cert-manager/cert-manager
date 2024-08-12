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

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// Runs a full set of tests against the trigger 'policy chain' once it is
// composed together.
// These tests account for the ordering of the policy chain, and are in place
// to ensure we do not break behaviour when introducing a new policy or
// modifying existing code.
func Test_NewTriggerPolicyChain(t *testing.T) {
	clock := &fakeclock.FakeClock{}
	staticFixedPrivateKey := testcrypto.MustCreatePEMPrivateKey(t)
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
			reason:      DoesNotExist,
			message:     "Issuing certificate as Secret does not exist",
			reissue:     true,
		},
		"trigger issuance as Secret does not contain any data": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret:      &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"}},
			reason:      MissingData,
			message:     "Issuing certificate as Secret does not contain any data",
			reissue:     true,
		},
		"trigger issuance as Secret is missing private key": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{corev1.TLSCertKey: []byte("test")},
			},
			reason:  MissingData,
			message: "Issuing certificate as Secret does not contain a private key",
			reissue: true,
		},
		"trigger issuance as Secret is missing certificate": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{corev1.TLSPrivateKeyKey: []byte("test")},
			},
			reason:  MissingData,
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
			reason:  InvalidKeyPair,
			message: "Issuing certificate as Secret contains invalid private key data: error decoding private key PEM block",
			reissue: true,
		},
		"trigger issuance as Secret contains corrupt certificate data": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: testcrypto.MustCreatePEMPrivateKey(t),
					corev1.TLSCertKey:       []byte("test"),
				},
			},
			reason:  InvalidCertificate,
			message: "Issuing certificate as Secret contains an invalid certificate: error decoding certificate PEM block",
			reissue: true,
		},
		"trigger issuance as Secret contains corrupt private key data": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: []byte("invalid"),
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, testcrypto.MustCreatePEMPrivateKey(t),
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  InvalidKeyPair,
			message: "Issuing certificate as Secret contains invalid private key data: error decoding private key PEM block",
			reissue: true,
		},
		"trigger issuance as Secret contains a non-matching key-pair": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: testcrypto.MustCreatePEMPrivateKey(t),
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, testcrypto.MustCreatePEMPrivateKey(t),
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  InvalidKeyPair,
			message: "Issuing certificate as Secret contains a private key that does not match the certificate",
			reissue: true,
		},
		"trigger issuance as Secret has old or incorrect 'issuer name' annotation": {
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  IncorrectIssuer,
			message: "Issuing certificate as Secret was previously issued by \"Issuer.cert-manager.io/oldissuer\"",
			reissue: true,
		},
		"trigger issuance as Secret has old or incorrect 'issuer kind' annotation": {
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  IncorrectIssuer,
			message: "Issuing certificate as Secret was previously issued by \"OldIssuerKind.cert-manager.io/testissuer\"",
			reissue: true,
		},
		"trigger issuance as Secret has old or incorrect 'issuer group' annotation": {
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  IncorrectIssuer,
			message: "Issuing certificate as Secret was previously issued by \"IssuerKind.new.example.com/testissuer\"",
			reissue: true,
		},
		"trigger issuance as private key properties do not meet the requested properties": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: func() map[string][]byte {
					// generate a 521 bit EC private key, which is not the type of key
					// configured in the Certificate resource
					pk, err := pki.GenerateECPrivateKey(521)
					if err != nil {
						t.Fatal(err)
					}

					pkData, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
					if err != nil {
						t.Fatal(err)
					}

					return map[string][]byte{
						corev1.TLSPrivateKeyKey: pkData,
						corev1.TLSCertKey: testcrypto.MustCreateCert(
							t, pkData,
							&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
						),
					}
				}(),
			},
			reason:  SecretMismatch,
			message: "Existing private key is not up to date for spec: [spec.privateKey.algorithm]",
			reissue: true,
		},
		"trigger if the Secret contains a different private key than was used to sign the CSR": {
			certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "something"},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
					corev1.TLSCertKey: testcrypto.MustCreateCert(
						t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			request: &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{
				IssuerRef: cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				},
				Request: testcrypto.MustGenerateCSRImpl(t, testcrypto.MustCreatePEMPrivateKey(t), &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
				}}),
			}},
			reason:  SecretMismatch,
			message: "Secret contains a private key that does not match the current CertificateRequest",
			reissue: true,
		},
		// we only have a basic test here for this as unit tests for the
		// `pki.RequestMatchesSpec` function cover all other cases.
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
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
				Request: testcrypto.MustGenerateCSRImpl(t, staticFixedPrivateKey, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					CommonName: "old.example.com",
				}}),
			}},
			reason:  RequestChanged,
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
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
				Request: testcrypto.MustGenerateCSRImpl(t, staticFixedPrivateKey, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "old.example.com"}},
					),
				},
			},
			reason:  SecretMismatch,
			message: "Issuing certificate as Existing issued Secret is not up to date for spec: [spec.commonName]",
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
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
					corev1.TLSCertKey: testcrypto.MustCreateCertWithNotBeforeAfter(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
						clock.Now().Add(time.Minute*-30),
						// expires in 1 minute time
						clock.Now().Add(time.Minute*1),
					),
				},
			},
			reason:  Renewing,
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
					corev1.TLSCertKey: testcrypto.MustCreateCertWithNotBeforeAfter(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
						clock.Now().Add(time.Minute*-30),
						// expires in 1 minute time
						clock.Now().Add(time.Minute*1),
					),
				},
			},
			reason:  Renewing,
			message: "Renewing certificate as renewal was scheduled at 0000-12-31 23:59:00 +0000 UTC",
			reissue: true,
		},
		"does not trigger renewal if the x509 cert has been re-issued, but Certificate's renewal time has not been updated yet": {
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
					corev1.TLSCertKey: testcrypto.MustCreateCertWithNotBeforeAfter(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
						clock.Now(),
						// expires in 30 minutes time
						clock.Now().Add(time.Minute*30),
					),
				},
			},
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
					corev1.TLSCertKey: testcrypto.MustCreateCertWithNotBeforeAfter(t, staticFixedPrivateKey,
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

func Test_SecretManagedLabelsAndAnnotationsManagedFieldsMismatch(t *testing.T) {
	const fieldManager = "cert-manager-unit-test"

	var (
		fixedClockStart = time.Now()
		fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
		baseCertBundle  = testcrypto.MustCreateCryptoBundle(t,
			gen.Certificate("test-certificate", gen.SetCertificateCommonName("cert-manager")), fixedClock)
	)

	tests := map[string]struct {
		secretManagedFields []metav1.ManagedFieldsEntry
		secretData          map[string][]byte

		expReason    string
		expMessage   string
		expViolation bool
	}{
		"if there are no cert-manager annotations and the certificate data is nil, should return false": {
			secretManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:labels": {
								"f:controller.cert-manager.io/fao": {}
							}
						}}`),
				}},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if optional cert-manager annotations are present with no certificate data, should return false": {
			secretManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:labels": {
								"f:controller.cert-manager.io/fao": {}
							},
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {},
								"f:cert-manager.io/certificate-name": {},
								"f:cert-manager.io/issuer-name": {},
								"f:cert-manager.io/issuer-kind": {},
								"f:cert-manager.io/issuer-group": {}
							}
						}}`),
				}},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if cert-manager annotations are present with certificate data, should return false": {
			secretManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:labels": {
								"f:controller.cert-manager.io/fao": {}
							},
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {},
								"f:cert-manager.io/certificate-name": {},
								"f:cert-manager.io/issuer-name": {},
								"f:cert-manager.io/issuer-kind": {},
								"f:cert-manager.io/issuer-group": {},
								"f:cert-manager.io/common-name": {},
								"f:cert-manager.io/alt-names":  {},
								"f:cert-manager.io/ip-sans": {},
								"f:cert-manager.io/uri-sans": {}
							}
						}}`),
				}},
			},
			secretData:   map[string][]byte{corev1.TLSCertKey: baseCertBundle.CertBytes},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if required and optional cert-manager annotations are present with certificate data but certificate data is nil, should return true": {
			secretManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:labels": {
								"f:controller.cert-manager.io/fao": {}
							},
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {},
								"f:cert-manager.io/certificate-name": {},
								"f:cert-manager.io/issuer-name": {},
								"f:cert-manager.io/issuer-kind": {},
								"f:cert-manager.io/issuer-group": {},
								"f:cert-manager.io/uri-sans": {},
								"f:cert-manager.io/ip-sans": {}
							}
						}}`),
				}},
			},
			expReason:    SecretManagedMetadataMismatch,
			expMessage:   "Secret has these extra Annotations: [cert-manager.io/ip-sans cert-manager.io/uri-sans]",
			expViolation: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotReason, gotMessage, gotViolation := SecretManagedLabelsAndAnnotationsManagedFieldsMismatch(fieldManager)(Input{
				Secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{ManagedFields: test.secretManagedFields}, Data: test.secretData},
			})

			assert.Equal(t, test.expReason, gotReason, "unexpected reason")
			assert.Equal(t, test.expMessage, gotMessage, "unexpected message")
			assert.Equal(t, test.expViolation, gotViolation, "unexpected violation")
		})
	}
}

func Test_SecretSecretTemplateMismatch(t *testing.T) {
	tests := map[string]struct {
		tmpl         *cmapi.CertificateSecretTemplate
		secret       *corev1.Secret
		expViolation bool
		expReason    string
		expMessage   string
	}{
		"if SecretTemplate is nil, Secret Annotations and Labels are nil, return false": {
			tmpl:         nil,
			secret:       &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: nil, Labels: nil}},
			expViolation: false,
			expReason:    "",
			expMessage:   "",
		},
		"if SecretTemplate is nil, Secret Annotations are nil, Labels are non-nil, return false": {
			tmpl:         nil,
			secret:       &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: nil, Labels: map[string]string{"foo": "bar"}}},
			expViolation: false,
			expReason:    "",
			expMessage:   "",
		},
		"if SecretTemplate is nil, Secret Annotations are non-nil, Labels are nil, return false": {
			tmpl:         nil,
			secret:       &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"foo": "bar"}, Labels: nil}},
			expViolation: false,
			expReason:    "",
			expMessage:   "",
		},
		"if SecretTemplate is nil, Secret Annotations and Labels are non-nil, return false": {
			tmpl: nil,
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo": "bar"},
				Labels:      map[string]string{"bar": "foo"},
			}},
			expViolation: false,
			expReason:    "",
			expMessage:   "",
		},
		"if SecretTemplate is non-nil, Secret Annotations match and there are no common Labels, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      nil,
			}},
			expViolation: false,
			expReason:    "",
			expMessage:   "",
		},
		"if SecretTemplate is non-nil, Secret Labels match and there are no common Annotations, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: nil,
				Labels:      map[string]string{"abc": "123", "def": "456"},
			}},
			expViolation: false,
			expReason:    "",
			expMessage:   "",
		},
		"if SecretTemplate is non-nil, Secret Labels match but Annotations don't match values, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar2", "foo2": "bar1"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			}},
			expViolation: true,
			expReason:    SecretTemplateMismatch,
			expMessage:   "Certificate's SecretTemplate Annotations missing or incorrect value on Secret",
		},
		"if SecretTemplate is non-nil, Secret Annotations match but Labels don't match values, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "456", "def": "123"},
			}},
			expViolation: true,
			expReason:    SecretTemplateMismatch,
			expMessage:   "Certificate's SecretTemplate Labels missing or incorrect value on Secret",
		},
		"if SecretTemplate is non-nil, Secret Annotations and Labels match, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			}},
			expViolation: false,
			expReason:    "",
			expMessage:   "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotReason, gotMessage, gotViolation := SecretSecretTemplateMismatch(Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretTemplate: test.tmpl}},
				Secret:      test.secret,
			})

			assert.Equal(t, test.expReason, gotReason, "unexpected reason")
			assert.Equal(t, test.expMessage, gotMessage, "unexpected message")
			assert.Equal(t, test.expViolation, gotViolation, "unexpected violation")
		})
	}
}

func Test_SecretSecretTemplateManagedFieldsMismatch(t *testing.T) {
	const fieldManager = "cert-manager-unit-test"

	tests := map[string]struct {
		tmpl                *cmapi.CertificateSecretTemplate
		secretManagedFields []metav1.ManagedFieldsEntry

		expReason    string
		expMessage   string
		expViolation bool
	}{
		"if template is nil and no managed fields, should return false": {
			tmpl:                nil,
			secretManagedFields: nil,
			expReason:           "",
			expMessage:          "",
			expViolation:        false,
		},
		"if template is nil, managed fields is not nil but not managed by cert-manager, should return false": {
			tmpl: nil,
			secretManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: "not-cert-manager", FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:bar": {}
							},
							"f:labels": {
								"f:123": {}
							}
						}}`),
				}},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if template is nil, managed fields is not nil but fields are nil, should return false": {
			tmpl:                nil,
			secretManagedFields: []metav1.ManagedFieldsEntry{{Manager: fieldManager, FieldsV1: nil}},
			expReason:           "",
			expMessage:          "",
			expViolation:        false,
		},
		"if template is not-nil but managed fields is nil, should return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo": "bar"},
				Labels:      map[string]string{"abc": "123"},
			},
			secretManagedFields: nil,
			expReason:           SecretTemplateMismatch,
			expMessage:          "Secret is missing these Template Labels: [abc]",
			expViolation:        true,
		},
		"if template is nil but managed fields is not nil, should return true": {
			tmpl: nil,
			secretManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo": {}
							},
							"f:labels": {
								"f:abc": {}
							}
						}}`),
				}},
			},
			expReason:    SecretTemplateMismatch,
			expMessage:   "Secret has these extra Labels: [abc]",
			expViolation: true,
		},
		"if template annotations do not match managed fields, should return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2", "foo4": "bar4"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo3": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expReason:    SecretTemplateMismatch,
			expMessage:   "Secret is missing these Template Annotations: [foo2 foo4]",
			expViolation: true,
		},
		"if template labels do not match managed fields, should return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456", "ghi": "789"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:erg": {}
							}
						}}`),
				}},
			},
			expReason:    SecretTemplateMismatch,
			expMessage:   "Secret is missing these Template Labels: [def ghi]",
			expViolation: true,
		},
		"if template annotations and labels match managed fields, should return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if template annotations is a subset of managed fields, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {},
								"f:foo3": {},
								"f:foo4": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expReason:    SecretTemplateMismatch,
			expMessage:   "Secret has these extra Annotations: [foo3 foo4]",
			expViolation: true,
		},
		"if template labels is a subset of managed fields, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {},
								"f:ghi": {},
								"f:jkl": {}
							}
						}}`),
				}},
			},
			expReason:    SecretTemplateMismatch,
			expMessage:   "Secret has these extra Labels: [ghi jkl]",
			expViolation: true,
		},
		"if managed fields annotations is a subset of template, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2", "foo3": "bar3"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expReason:    SecretTemplateMismatch,
			expMessage:   "Secret is missing these Template Annotations: [foo3]",
			expViolation: true,
		},
		"if managed fields labels is a subset of template, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456", "ghi": "789"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expReason:    SecretTemplateMismatch,
			expMessage:   "Secret is missing these Template Labels: [ghi]",
			expViolation: true,
		},
		"if managed fields matches template but is split across multiple managed fields, should return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2", "foo3": "bar3"},
				Labels:      map[string]string{"abc": "123", "def": "456", "ghi": "789"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:labels": {
								"f:ghi": {}
							}
						}}`),
				}},
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo3": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
				{Manager: fieldManager,
					FieldsV1: &metav1.FieldsV1{
						Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
					}},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if managed fields matches template and cert-manager annotations are present, should return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {},
								"f:cert-manager.io/foo1": {},
								"f:cert-manager.io/foo2": {}
							}
						}}`),
				}},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotReason, gotMessage, gotViolation := SecretSecretTemplateManagedFieldsMismatch(fieldManager)(Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretTemplate: test.tmpl}},
				Secret:      &corev1.Secret{ObjectMeta: metav1.ObjectMeta{ManagedFields: test.secretManagedFields}, Data: map[string][]byte{}},
			})

			assert.Equal(t, test.expReason, gotReason, "unexpected reason")
			assert.Equal(t, test.expMessage, gotMessage, "unexpected message")
			assert.Equal(t, test.expViolation, gotViolation, "unexpected violation")
		})
	}
}

func Test_SecretAdditionalOutputFormatsMismatch(t *testing.T) {
	cert := []byte("a")
	pk := testcrypto.MustCreatePEMPrivateKey(t)
	block, _ := pem.Decode(pk)
	pkDER := block.Bytes
	combinedPEM := append(append(pk, '\n'), cert...)

	tests := map[string]struct {
		input        Input
		expReason    string
		expMessage   string
		expViolation bool
	}{
		"if additional output formats is empty and secret has no keys, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{},
				Secret:      &corev1.Secret{},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output formats is empty and secret has output format keys, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt":          cert,
						"tls.key":          pk,
						"combined-tls.pem": combinedPEM,
						"key.der":          pkDER,
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output has combined pem and Secret has wrong combined, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt":          cert,
						"tls.key":          pk,
						"tls-combined.pem": []byte("wrong"),
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret Data",
			expViolation: true,
		},
		"if additional output has combined pem and Secret has no combined pem, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt": cert,
						"tls.key": pk,
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret Data",
			expViolation: true,
		},
		"if additional output has combined pem and Secret has correct combined, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt":          cert,
						"tls.key":          pk,
						"tls-combined.pem": combinedPEM,
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output has der and Secret has no key, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt": cert,
						"tls.key": pk,
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret Data",
			expViolation: true,
		},
		"if additional output has der and Secret has wrong der key, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt": cert,
						"tls.key": pk,
						"key.der": []byte("wrong"),
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret Data",
			expViolation: true,
		},
		"if additional output has der and Secret has correct der key, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt": cert,
						"tls.key": pk,
						"key.der": pkDER,
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output has combined and der and Secret has correct combined and der, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt":          cert,
						"tls.key":          pk,
						"key.der":          pkDER,
						"tls-combined.pem": combinedPEM,
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output has combined and der and Secret has correct combined and wrong der value, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt":          cert,
						"tls.key":          pk,
						"key.der":          []byte("wrong"),
						"tls-combined.pem": combinedPEM,
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret Data",
			expViolation: true,
		},
		"if additional output has combined and der and Secret has wrong combined value and correct der value, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt":          cert,
						"tls.key":          pk,
						"key.der":          pkDER,
						"tls-combined.pem": []byte("wrong"),
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret Data",
			expViolation: true,
		},
		"if additional output has combined and der and Secret has correct combined value and missing der key, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt":          cert,
						"tls.key":          pk,
						"tls-combined.pem": combinedPEM,
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret Data",
			expViolation: true,
		},
		"if additional output has combined and der and Secret has missing combined key and correct der value, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt": cert,
						"tls.key": pk,
						"key.der": pkDER,
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret Data",
			expViolation: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotReason, gotMessage, gotViolation := SecretAdditionalOutputFormatsMismatch(test.input)
			assert.Equal(t, test.expReason, gotReason)
			assert.Equal(t, test.expMessage, gotMessage)
			assert.Equal(t, test.expViolation, gotViolation)
		})
	}
}

func Test_SecretAdditionalOutputFormatsManagedFieldsMismatch(t *testing.T) {
	const fieldManager = "cert-manager-test"

	tests := map[string]struct {
		input        Input
		expReason    string
		expMessage   string
		expViolation bool
	}{
		"if additional output formats is empty and secret has no managed fields, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{},
				Secret:      &corev1.Secret{},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output formats has combined pem and secret has no managed fields, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
					}},
				},
				Secret: &corev1.Secret{},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields",
			expViolation: true,
		},
		"if additional output formats has der and secret has no managed fields, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields",
			expViolation: true,
		},
		"if additional output formats has combined pem and der, and secret has no managed fields, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields",
			expViolation: true,
		},
		"if additional output formats is empty, and secret has managed fields for combined pem for another managed, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "not-cert-manager", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
							  "f:tls-combined.pem": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output formats is empty, and secret has managed fields for der for another managed, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "not-cert-manager", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
							  "f:key.der": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output formats is empty, and secret has managed fields for combined pem and der for another managed, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "not-cert-manager", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
							  "f:tls-combined.pem": {},
							  "f:key.der": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output formats is empty, and secret has managed fields for combined pem, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
							  "f:tls-combined.pem": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields",
			expViolation: true,
		},
		"if additional output formats is empty, and secret has managed fields for der, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
							  "f:key.der": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields",
			expViolation: true,
		},
		"if additional output formats is empty, and secret has managed fields for combined pem and der, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:tls-combined.pem": {},
							  "f:key.der": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields",
			expViolation: true,
		},
		"if additional output formats has combined pem, and secret has managed fields for combined pem for wrong manager, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
					}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "not-cert-manager", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:tls-combined.pem": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields",
			expViolation: true,
		},
		"if additional output formats has der, and secret has managed fields for der for wrong manager, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "not-cert-manager", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:key.der": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields",
			expViolation: true,
		},
		"if additional output formats has combined pem and der, and secret has managed fields for combined pem and der for wrong manager, should return true": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "not-cert-manager", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:tls-combined.pem": {},
								"f:key.der": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "AdditionalOutputFormatsMismatch",
			expMessage:   "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields",
			expViolation: true,
		},
		"if additional output formats has combined pem, and secret has managed fields for combined pem, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
					}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:tls-combined.pem": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output formats has der, and secret has managed fields for der, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
					}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:key.der": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output formats has combined pem and der, and secret has managed fields for combined pem and der, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
						{Type: "CombinedPEM"},
					}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:key.der": {},
								"f:tls-combined.pem": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output formats has combined pem and der, and secret has managed fields for combined pem and der in different slice elements, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
						{Type: "CombinedPEM"},
					}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:key.der": {}
							}}`),
							}},
							{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:tls-combined.pem": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"if additional output formats has combined pem and der, and secret has managed fields for combined pem and der, and is also managed by another manager, should return false": {
			input: Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
						{Type: "CombinedPEM"},
					}},
				},
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:tls-combined.pem": {},
								"f:key.der": {}
							}}`),
							}},
							{Manager: "not-cert-manager", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
              {"f:data": {
							  ".": {},
								"f:key.der": {},
								"f:tls-combined.pem": {}
							}}`),
							}},
						},
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotReason, gotMessage, gotViolation := SecretAdditionalOutputFormatsManagedFieldsMismatch(fieldManager)(test.input)
			assert.Equal(t, test.expReason, gotReason)
			assert.Equal(t, test.expMessage, gotMessage)
			assert.Equal(t, test.expViolation, gotViolation)
		})
	}
}

func Test_SecretOwnerReferenceManagedFieldMismatch(t *testing.T) {
	const fieldManager = "cert-manager-test"

	crt := gen.Certificate("test-certificate",
		gen.SetCertificateUID("uid-123"),
	)

	tests := map[string]struct {
		input           Input
		ownerRefEnabled bool

		expReason    string
		expMessage   string
		expViolation bool
	}{
		"ownerReferenceEnabled=false no secret managed field owner reference should return false": {
			input: Input{
				Certificate: crt,
				Secret:      &corev1.Secret{},
			},
			ownerRefEnabled: false,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},
		"ownerReferenceEnabled=false secret managed field owner reference for different UID should return false": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "cert-manager-test", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
                {"f:metadata": {
								"f:ownerReferences": {
                "k:{\"uid\":\"4c71e68f-5271-4b8d-9df5-5eb71d130d7d\"}": {}
							}}}`),
							}},
						},
					},
				},
			},
			ownerRefEnabled: false,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},
		"ownerReferenceEnabled=false secret managed field owner reference for same UID should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "cert-manager-test", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
                {"f:metadata": {
								"f:ownerReferences": {
                "k:{\"uid\":\"uid-123\"}": {}
							}}}`),
							}},
						},
					},
				},
			},
			ownerRefEnabled: false,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected managed Secret Owner Reference field on Secret --enable-certificate-owner-ref=false",
			expViolation:    true,
		},
		"ownerReferenceEnabled=false secret managed field different owner reference for same UID should return false": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "not-cert-manager-test", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
                {"f:metadata": {
								"f:ownerReferences": {
                "k:{\"uid\":\"uid-123\"}": {}
							}}}`),
							}},
						},
					},
				},
			},
			ownerRefEnabled: false,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},

		"ownerReferenceEnabled=true no secret managed field owner reference should return true": {
			input: Input{
				Certificate: crt,
				Secret:      &corev1.Secret{},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected managed Secret Owner Reference field on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
		"ownerReferenceEnabled=true secret managed field owner reference for different UID should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "cert-manager-test", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
                {"f:metadata": {
								"f:ownerReferences": {
                "k:{\"uid\":\"4c71e68f-5271-4b8d-9df5-5eb71d130d7d\"}": {}
							}}}`),
							}},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected managed Secret Owner Reference field on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
		"ownerReferenceEnabled=true secret managed field owner reference for same UID should return false": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "cert-manager-test", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
                {"f:metadata": {
								"f:ownerReferences": {
                "k:{\"uid\":\"uid-123\"}": {}
							}}}`),
							}},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},
		"ownerReferenceEnabled=true secret managed field different owner reference for same UID should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						ManagedFields: []metav1.ManagedFieldsEntry{
							{Manager: "not-cert-manager-test", FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`
                {"f:metadata": {
								"f:ownerReferences": {
                "k:{\"uid\":\"uid-123\"}": {}
							}}}`),
							}},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected managed Secret Owner Reference field on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotReason, gotMessage, gotViolation := SecretOwnerReferenceManagedFieldMismatch(test.ownerRefEnabled, fieldManager)(test.input)
			assert.Equal(t, test.expReason, gotReason)
			assert.Equal(t, test.expMessage, gotMessage)
			assert.Equal(t, test.expViolation, gotViolation)
		})
	}
}

func Test_SecretOwnerReferenceMismatch(t *testing.T) {
	crt := gen.Certificate("test-certificate",
		gen.SetCertificateUID("uid-123"),
	)

	tests := map[string]struct {
		input           Input
		ownerRefEnabled bool

		expReason    string
		expMessage   string
		expViolation bool
	}{
		"ownerReferenceEnabled=false no secret owner reference should return false": {
			input: Input{
				Certificate: crt,
				Secret:      &corev1.Secret{},
			},
			ownerRefEnabled: false,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},
		"ownerReferenceEnabled=false secret has random owner reference should return false": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
						},
					},
				},
			},
			ownerRefEnabled: false,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},
		"ownerReferenceEnabled=false secret has multiple random owner reference should return false": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
						},
					},
				},
			},
			ownerRefEnabled: false,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},
		"ownerReferenceEnabled=false secret has owner reference for certificate with correct value should return false": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
						},
					},
				},
			},
			ownerRefEnabled: false,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},
		"ownerReferenceEnabled=false secret has owner reference for certificate with in-correct value should return false": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "foo", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
						},
					},
				},
			},
			ownerRefEnabled: false,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},

		"ownerReferenceEnabled=false no secret owner reference should return true": {
			input: Input{
				Certificate: crt,
				Secret:      &corev1.Secret{},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
		"ownerReferenceEnabled=true secret has random owner reference should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
		"ownerReferenceEnabled=true secret has multiple random owner reference should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
		"ownerReferenceEnabled=true secret has owner reference for certificate with correct value should return false": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "",
			expMessage:      "",
			expViolation:    false,
		},
		"ownerReferenceEnabled=true secret has owner reference for certificate with wrong Name value should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "foo", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
		"ownerReferenceEnabled=true secret has owner reference for certificate with wrong APIVersion value should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
							{APIVersion: "acme.cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
		"ownerReferenceEnabled=true secret has owner reference for certificate with wrong Kind value should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Issuer", Name: "test-certificate", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
		"ownerReferenceEnabled=true secret has owner reference for certificate with wrong Controller value should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(true)},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
		"ownerReferenceEnabled=true secret has owner reference for certificate with wrong BlockDeletion value should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						OwnerReferences: []metav1.OwnerReference{
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(false)},
						},
					},
				},
			},
			ownerRefEnabled: true,
			expReason:       "SecretOwnerRefMismatch",
			expMessage:      "unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=true",
			expViolation:    true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotReason, gotMessage, gotViolation := SecretOwnerReferenceMismatch(test.ownerRefEnabled)(test.input)
			assert.Equal(t, test.expReason, gotReason)
			assert.Equal(t, test.expMessage, gotMessage)
			assert.Equal(t, test.expViolation, gotViolation)
		})
	}
}

func Test_SecretCertificateNameAnnotationsMismatch(t *testing.T) {
	crt := gen.Certificate("test-certificate")

	tests := map[string]struct {
		input Input

		expReason    string
		expMessage   string
		expViolation bool
	}{
		"without a CertificateName annotation, should return false": {
			input: Input{
				Certificate: crt,
				Secret:      &corev1.Secret{},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"with a matching CertificateName annotation, should return false": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							cmapi.CertificateNameKey: "test-certificate",
						},
					},
				},
			},
			expReason:    "",
			expMessage:   "",
			expViolation: false,
		},
		"with a non-matching CertificateName annotation, should return true": {
			input: Input{
				Certificate: crt,
				Secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							cmapi.CertificateNameKey: "foo",
						},
					},
				},
			},
			expReason:    "IncorrectCertificate",
			expMessage:   "Secret was issued for \"foo\". If this message is not transient, you might have two conflicting Certificates pointing to the same secret.",
			expViolation: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotReason, gotMessage, gotViolation := SecretCertificateNameAnnotationsMismatch(test.input)
			assert.Equal(t, test.expReason, gotReason)
			assert.Equal(t, test.expMessage, gotMessage)
			assert.Equal(t, test.expViolation, gotViolation)
		})
	}
}
