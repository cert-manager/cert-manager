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
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/pointer"

	"github.com/cert-manager/cert-manager/bazel-cert-manager/external/com_github_pmezard_go_difflib/difflib"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
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
			message: "Issuing certificate as Secret contains an invalid key-pair: tls: failed to find any PEM data in certificate input",
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
			reason:  InvalidKeyPair,
			message: "Issuing certificate as Secret contains an invalid key-pair: tls: failed to find any PEM data in certificate input",
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
			message: "Issuing certificate as Secret contains an invalid key-pair: tls: failed to find any PEM data in key input",
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  IncorrectIssuer,
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  IncorrectIssuer,
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
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, staticFixedPrivateKey,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			reason:  IncorrectIssuer,
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

func Test_SecretTemplateMismatchesSecret(t *testing.T) {
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
		"if SecretTemplate is non-nil, Secret Annotations match but Labels are nil, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      nil,
			}},
			expViolation: true,
			expReason:    SecretTemplateMismatch,
			expMessage:   "Certificate's SecretTemplate Labels missing or incorrect value on Secret",
		},
		"if SecretTemplate is non-nil, Secret Labels match but Annotations are nil, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: nil,
				Labels:      map[string]string{"abc": "123", "def": "456"},
			}},
			expViolation: true,
			expReason:    SecretTemplateMismatch,
			expMessage:   "Certificate's SecretTemplate Annotations missing or incorrect value on Secret",
		},
		"if SecretTemplate is non-nil, Secret Labels match but Annotations don't match keys, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo2": "bar1", "foo1": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			}},
			expViolation: true,
			expReason:    SecretTemplateMismatch,
			expMessage:   "Certificate's SecretTemplate Annotations missing or incorrect value on Secret",
		},
		"if SecretTemplate is non-nil, Secret Annoations match but Labels don't match keys, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"def": "123", "abc": "456"},
			}},
			expViolation: true,
			expReason:    SecretTemplateMismatch,
			expMessage:   "Certificate's SecretTemplate Labels missing or incorrect value on Secret",
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
			gotReason, gotMessage, gotViolation := SecretTemplateMismatchesSecret(Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretTemplate: test.tmpl}},
				Secret:      test.secret,
			})

			assert.Equal(t, test.expReason, gotReason, "unexpected reason")
			assert.Equal(t, test.expMessage, gotMessage, "unexpected message")
			assert.Equal(t, test.expViolation, gotViolation, "unexpected violation")
		})
	}
}

func Test_SecretTemplateMismatchesSecretManagedFields(t *testing.T) {
	const fieldManager = "cert-manager-unit-test"

	var (
		fixedClockStart = time.Now()
		fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
		baseCertBundle  = testcrypto.MustCreateCryptoBundle(t,
			gen.Certificate("test-certificate", gen.SetCertificateCommonName("cert-manager")), fixedClock)
	)

	tests := map[string]struct {
		tmpl                *cmapi.CertificateSecretTemplate
		secretManagedFields []metav1.ManagedFieldsEntry
		secretData          map[string][]byte

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
			expMessage:          "Certificate's SecretTemplate doesn't match Secret",
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
			expMessage:   "SecretTemplate is nil, but Secret contains extra managed entries",
			expViolation: true,
		},
		"if template annotations do not match managed fields, should return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
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
			expMessage:   "Certificate's SecretTemplate doesn't match Secret",
			expViolation: true,
		},
		"if template labels do not match managed fields, should return true": {
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
								"f:erg": {}
							}
						}}`),
				}},
			},
			expReason:    SecretTemplateMismatch,
			expMessage:   "Certificate's SecretTemplate doesn't match Secret",
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
			expMessage:   "Certificate's SecretTemplate doesn't match Secret",
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
								"f:ghi": {}
							}
						}}`),
				}},
			},
			expReason:    SecretTemplateMismatch,
			expMessage:   "Certificate's SecretTemplate doesn't match Secret",
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
			expMessage:   "Certificate's SecretTemplate doesn't match Secret",
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
			expMessage:   "Certificate's SecretTemplate doesn't match Secret",
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
		"if managed fields matches template and base cert-manager annotations are present with no certificate data, should return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
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
		"if managed fields matches template and base cert-manager annotations are present with certificate data, should return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
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
			expViolation: false,
		},
		"if managed fields matches template and base cert-manager annotations are present with certificate data but certificate data is nil, should return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
			},
			secretManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
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
			expReason:    SecretTemplateMismatch,
			expMessage:   "Certificate's SecretTemplate doesn't match Secret",
			expViolation: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotReason, gotMessage, gotViolation := SecretTemplateMismatchesSecretManagedFields(fieldManager)(Input{
				Certificate: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretTemplate: test.tmpl}},
				Secret:      &corev1.Secret{ObjectMeta: metav1.ObjectMeta{ManagedFields: test.secretManagedFields}, Data: test.secretData},
			})

			assert.Equal(t, test.expReason, gotReason, "unexpected reason")
			assert.Equal(t, test.expMessage, gotMessage, "unexpected message")
			assert.Equal(t, test.expViolation, gotViolation, "unexpected violation")
		})
	}
}

func Test_SecretAdditionalOutputFormatsDataMismatch(t *testing.T) {
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
			gotReason, gotMessage, gotViolation := SecretAdditionalOutputFormatsDataMismatch(test.input)
			assert.Equal(t, test.expReason, gotReason)
			assert.Equal(t, test.expMessage, gotMessage)
			assert.Equal(t, test.expViolation, gotViolation)
		})
	}
}

func Test_SecretAdditionalOutputFormatsOwnerMismatch(t *testing.T) {
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
			gotReason, gotMessage, gotViolation := SecretAdditionalOutputFormatsOwnerMismatch(fieldManager)(test.input)
			assert.Equal(t, test.expReason, gotReason)
			assert.Equal(t, test.expMessage, gotMessage)
			assert.Equal(t, test.expViolation, gotViolation)
		})
	}
}

func Test_SecretOwnerReferenceManagedFieldMismatch(t *testing.T) {
	const fieldManager = "cert-manager-test"

	crt := gen.Certificate("test-certificate",
		gen.SetCertificateUID(types.UID("uid-123")),
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

func Test_SecretOwnerReferenceValueMismatch(t *testing.T) {
	crt := gen.Certificate("test-certificate",
		gen.SetCertificateUID(types.UID("uid-123")),
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "foo", UID: types.UID("uid-123"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "foo", UID: types.UID("uid-123"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
							{APIVersion: "acme.cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Issuer", Name: "test-certificate", UID: types.UID("uid-123"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(true)},
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
							{APIVersion: "foo.bar/v1", Kind: "Foo", Name: "foo", UID: types.UID("abc"), Controller: pointer.Bool(false), BlockOwnerDeletion: pointer.Bool(false)},
							{APIVersion: "bar.foo/v1", Kind: "Bar", Name: "bar", UID: types.UID("def"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
							{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-certificate", UID: types.UID("uid-123"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(false)},
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
			gotReason, gotMessage, gotViolation := SecretOwnerReferenceValueMismatch(test.ownerRefEnabled)(test.input)
			assert.Equal(t, test.expReason, gotReason)
			assert.Equal(t, test.expMessage, gotMessage)
			assert.Equal(t, test.expViolation, gotViolation)
		})
	}
}

func TestDefaultPolicyChain_triggerReIssuanceCases(t *testing.T) {
	type Cert *cmapi.Certificate // Those long types are making the lines go wee!
	type Sec *corev1.Secret
	clock := &fakeclock.FakeClock{}
	staticFixedPrivateKey := testcrypto.MustCreatePEMPrivateKey(t)

	originalCert := &cmapi.Certificate{Spec: cmapi.CertificateSpec{
		CommonName: "does-not-matter.example.com",
		Subject: &cmapi.X509Subject{
			Organizations:       []string{"org1", "org2"},
			Countries:           []string{"us"},
			OrganizationalUnits: []string{"ou1", "ou2"},
			Localities:          []string{"loc1", "loc2"},
			Provinces:           []string{"prov1", "prov2"},
			StreetAddresses:     []string{"street1", "street2"},
			PostalCodes:         []string{"post1", "post2"},
			SerialNumber:        "12345",
		},
		Duration:       &metav1.Duration{Duration: 30 * 24 * time.Hour},
		RenewBefore:    &metav1.Duration{Duration: 90 * 24 * time.Hour},
		DNSNames:       []string{"example.com"},
		IPAddresses:    []string{"1.2.3.4"},
		URIs:           []string{"http://example.com"},
		EmailAddresses: []string{"foo@bar.com"},
		SecretName:     "does-not-matter",
		SecretTemplate: &cmapi.CertificateSecretTemplate{
			Labels: map[string]string{"foo": "bar"},
		},
		Keystores: &cmapi.CertificateKeystores{
			JKS: &cmapi.JKSKeystore{
				Create: true,
				PasswordSecretRef: cmmeta.SecretKeySelector{
					Key:                  "password",
					LocalObjectReference: cmmeta.LocalObjectReference{Name: "foo"},
				},
			},
			PKCS12: &cmapi.PKCS12Keystore{
				Create: true,
				PasswordSecretRef: cmmeta.SecretKeySelector{
					Key:                  "password",
					LocalObjectReference: cmmeta.LocalObjectReference{Name: "foo"},
				},
			},
		},
		IssuerRef: cmmeta.ObjectReference{
			Name:  "testissuer",
			Kind:  "IssuerKind",
			Group: "group.example.com",
		},
		IsCA: true,
		Usages: []cmapi.KeyUsage{
			cmapi.UsageSigning,
			cmapi.UsageDigitalSignature,
			cmapi.UsageKeyEncipherment,
		},
		PrivateKey: &cmapi.CertificatePrivateKey{
			Algorithm:      cmapi.RSAKeyAlgorithm,
			Size:           2048,
			RotationPolicy: cmapi.RotationPolicyNever,
			Encoding:       cmapi.PKCS8,
		},
		EncodeUsagesInRequest: pointer.Bool(true),
		RevisionHistoryLimit:  pointer.Int32(2),
	}}
	originalSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "something",
			Annotations: map[string]string{
				cmapi.IssuerNameAnnotationKey:  "testissuer",
				cmapi.IssuerKindAnnotationKey:  "IssuerKind",
				cmapi.IssuerGroupAnnotationKey: "group.example.com",
			},
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: staticFixedPrivateKey,
			corev1.TLSCertKey:       testcrypto.MustCreateCert(t, staticFixedPrivateKey, originalCert),
		},
	}
	originalCR := &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{
		IssuerRef: cmmeta.ObjectReference{
			Name:  "testissuer",
			Kind:  "IssuerKind",
			Group: "group.example.com",
		},
		Request: testcrypto.MustGenerateCSRImpl(t, staticFixedPrivateKey, originalCert),
		IsCA:    true,
		Usages: []cmapi.KeyUsage{
			cmapi.UsageSigning,
			cmapi.UsageDigitalSignature,
			cmapi.UsageKeyEncipherment,
		},
		Duration: &metav1.Duration{Duration: 30 * 24 * time.Hour},
	}}

	tests := []struct {
		noCR     bool // When true, pretend that the CertificateRequest was not found.
		noSecret bool // When true, pretend that the Secret was not found.

		// Note that we do not test with changes to the CertificateRequest
		// because this resource is supposed to be immutable.
		c func(c Cert) // Change to the Certificate. Nil if no change is to be made.
		s func(s Sec)  // Change to the Secret. Nil if no change is to be made.

		reissue bool
		msg     string // The reason followed by ": " and followed by the message.
	}{
		// Happy case: with no change to the Certificate nor the Secret, and
		// with or without the CertificateRequest available, no re-issuance is
		// expected.
		{noCR: false, reissue: false},
		{noCR: true, reissue: false},

		// When the Secret is missing or broken, a re-issuance is expected.
		{noCR: true, noSecret: true, reissue: true,
			msg: "DoesNotExist: Issuing certificate as Secret does not exist"},
		{noCR: true, s: func(s Sec) { s.Data = nil }, reissue: true,
			msg: "MissingData: Issuing certificate as Secret does not contain any data"},
		{noCR: true, s: func(s Sec) { s.Data[corev1.TLSPrivateKeyKey] = nil }, reissue: true,
			msg: "MissingData: Issuing certificate as Secret does not contain a private key"},
		{noCR: true, s: func(s Sec) { s.Data[corev1.TLSCertKey] = nil }, reissue: true,
			msg: "MissingData: Issuing certificate as Secret does not contain a certificate"},
		{noCR: true, s: func(s Sec) { s.Data[corev1.TLSPrivateKeyKey] = []byte("invalid") }, reissue: true,
			msg: "InvalidKeyPair: Issuing certificate as Secret contains an invalid key-pair: tls: failed to find any PEM data in key input"},
		{noCR: true, s: func(s Sec) { s.Data[corev1.TLSCertKey] = []byte("invalid") }, reissue: true,
			msg: "InvalidKeyPair: Issuing certificate as Secret contains an invalid key-pair: tls: failed to find any PEM data in certificate input"},
		{noCR: true, s: func(s Sec) { s.Data[corev1.TLSPrivateKeyKey] = testcrypto.MustCreatePEMPrivateKey(t) }, reissue: true,
			msg: "InvalidKeyPair: Issuing certificate as Secret contains an invalid key-pair: tls: private key does not match public key"},
		{noCR: true, s: func(s Sec) { s.Annotations["cert-manager.io/issuer-name"] = "change" }, reissue: true,
			msg: "IncorrectIssuer: Issuing certificate as Secret was previously issued by IssuerKind.group.example.com/change"},
		{noCR: true, s: func(s Sec) { s.Annotations["cert-manager.io/issuer-kind"] = "change" }, reissue: true,
			msg: "IncorrectIssuer: Issuing certificate as Secret was previously issued by change.group.example.com/testissuer"},
		{noCR: true, s: func(s Sec) { s.Annotations["cert-manager.io/issuer-group"] = "change" }, reissue: true,
			msg: "IncorrectIssuer: Issuing certificate as Secret was previously issued by IssuerKind.change/testissuer"},

		// When only the Secret is available, changing onf of the following
		// fields are expected to trigger a re-issuance.
		{noCR: true, c: func(c Cert) { c.Spec.CommonName = "changed" }, reissue: true,
			msg: "SecretMismatch: Existing issued Secret is not up to date for spec: [spec.commonName]"},
		{noCR: true, c: func(c Cert) { c.Spec.DNSNames = []string{"changed"} }, reissue: true,
			msg: "SecretMismatch: Existing issued Secret is not up to date for spec: [spec.dnsNames]"},
		{noCR: true, c: func(c Cert) { c.Spec.IPAddresses = []string{"4.3.2.1"} }, reissue: true,
			msg: "SecretMismatch: Existing issued Secret is not up to date for spec: [spec.ipAddresses]"},
		{noCR: true, c: func(c Cert) { c.Spec.URIs = []string{"https://changed"} }, reissue: true,
			msg: "SecretMismatch: Existing issued Secret is not up to date for spec: [spec.uris]"},
		{noCR: true, c: func(c Cert) { c.Spec.EmailAddresses = []string{"changed@bar.com"} }, reissue: true,
			msg: "SecretMismatch: Existing issued Secret is not up to date for spec: [spec.emailAddresses]"},
		{noCR: true, c: func(c Cert) { c.Spec.IssuerRef = cmmeta.ObjectReference{Name: "changed"} }, reissue: true,
			msg: "IncorrectIssuer: Issuing certificate as Secret was previously issued by IssuerKind.group.example.com/testissuer"},
		{noCR: true, c: func(c Cert) { c.Spec.PrivateKey.Algorithm = cmapi.ECDSAKeyAlgorithm }, reissue: true,
			msg: "SecretMismatch: Existing private key is not up to date for spec: [spec.keyAlgorithm]"},
		{noCR: true, c: func(c Cert) { c.Spec.PrivateKey.Size = 4096 }, reissue: true,
			msg: "SecretMismatch: Existing private key is not up to date for spec: [spec.keySize]"},

		// When only the Secret is available,  changing one of the following
		// fields does not trigger a re-issuance.
		{noCR: true, c: func(c Cert) { c.Spec.Usages = []cmapi.KeyUsage{cmapi.UsageAny} }, reissue: false},
		{noCR: true, c: func(c Cert) { c.Spec.IsCA = false }, reissue: false},
		{noCR: true, c: func(c Cert) { c.Spec.Duration = &metav1.Duration{Duration: 1 * time.Hour} }, reissue: false},
		{noCR: true, c: func(c Cert) { c.Spec.EncodeUsagesInRequest = pointer.Bool(false) }, reissue: false},
		{noCR: true, c: func(c Cert) { c.Spec.Keystores = &cmapi.CertificateKeystores{} }, reissue: false},
		{noCR: true, c: func(c Cert) { c.Spec.RenewBefore = &metav1.Duration{Duration: 1 * time.Hour} }, reissue: false},
		{noCR: true, c: func(c Cert) { c.Spec.RevisionHistoryLimit = pointer.Int32(10) }, reissue: false},
		{noCR: true, c: func(c Cert) { c.Spec.SecretName = "changed" }, reissue: false}, // (1)
		{noCR: true, c: func(c Cert) { c.Spec.SecretTemplate = &cmapi.CertificateSecretTemplate{} }, reissue: false},
		{noCR: true, c: func(c Cert) { c.Spec.PrivateKey.Encoding = cmapi.PKCS1 }, reissue: false},
		{noCR: true, c: func(c Cert) { c.Spec.PrivateKey.RotationPolicy = cmapi.RotationPolicyAlways }, reissue: false},

		// When both the Secret and the CertificateRequest are available,
		// changing one of the following fields is expected to trigger a
		// re-issuance.
		{c: func(c Cert) { c.Spec.CommonName = "changed" }, reissue: true,
			msg: "RequestChanged: Fields on existing CertificateRequest resource not up to date: [spec.commonName]"},
		{c: func(c Cert) { c.Spec.DNSNames = []string{"changed"} }, reissue: true,
			msg: "RequestChanged: Fields on existing CertificateRequest resource not up to date: [spec.dnsNames]"},
		{c: func(c Cert) { c.Spec.IPAddresses = []string{"4.3.2.1"} }, reissue: true,
			msg: "RequestChanged: Fields on existing CertificateRequest resource not up to date: [spec.ipAddresses]"},
		{c: func(c Cert) { c.Spec.URIs = []string{"https://changed"} }, reissue: true,
			msg: "RequestChanged: Fields on existing CertificateRequest resource not up to date: [spec.uris]"},
		{c: func(c Cert) { c.Spec.EmailAddresses = []string{"changed@bar.com"} }, reissue: true,
			msg: "RequestChanged: Fields on existing CertificateRequest resource not up to date: [spec.emailAddresses]"},
		{c: func(c Cert) { c.Spec.Usages = []cmapi.KeyUsage{cmapi.UsageAny} }, reissue: true,
			msg: "RequestChanged: Fields on existing CertificateRequest resource not up to date: [spec.usages]"},
		{c: func(c Cert) { c.Spec.IsCA = false }, reissue: true,
			msg: "RequestChanged: Fields on existing CertificateRequest resource not up to date: [spec.isCA]"},
		{c: func(c Cert) { c.Spec.Duration = &metav1.Duration{Duration: 1 * time.Hour} }, reissue: true,
			msg: "RequestChanged: Fields on existing CertificateRequest resource not up to date: [spec.duration]"},
		{c: func(c Cert) { c.Spec.IssuerRef = cmmeta.ObjectReference{Name: "changed"} }, reissue: true,
			msg: "IncorrectIssuer: Issuing certificate as Secret was previously issued by IssuerKind.group.example.com/testissuer"},
		{c: func(c Cert) { c.Spec.PrivateKey.Algorithm = cmapi.ECDSAKeyAlgorithm }, reissue: true,
			msg: "SecretMismatch: Existing private key is not up to date for spec: [spec.keyAlgorithm]"},
		{c: func(c Cert) { c.Spec.PrivateKey.Size = 4096 }, reissue: true,
			msg: "SecretMismatch: Existing private key is not up to date for spec: [spec.keySize]"},

		// When both the Secret and the CertificateRequest are available,
		// changing one of the following fields does not trigger a re-issuance.
		{c: func(c Cert) { c.Spec.EncodeUsagesInRequest = pointer.Bool(false) }, reissue: false},
		{c: func(c Cert) { c.Spec.Keystores = &cmapi.CertificateKeystores{} }, reissue: false},
		{c: func(c Cert) { c.Spec.RenewBefore = &metav1.Duration{Duration: 1 * time.Hour} }, reissue: false},
		{c: func(c Cert) { c.Spec.RevisionHistoryLimit = pointer.Int32(10) }, reissue: false},
		{c: func(c Cert) { c.Spec.SecretName = "changed" }, reissue: false}, // (1)
		{c: func(c Cert) { c.Spec.SecretTemplate = &cmapi.CertificateSecretTemplate{} }, reissue: false},
		{c: func(c Cert) { c.Spec.PrivateKey.Encoding = cmapi.PKCS1 }, reissue: false},
		{c: func(c Cert) { c.Spec.PrivateKey.RotationPolicy = cmapi.RotationPolicyAlways }, reissue: false},

		// (1) You might be surprised to see reissue=false for the secretName
		// field. That's because this case is actually handled in the test case
		// "both Secret and CR not found, should reissue".
	}
	policyChain := NewTriggerPolicyChain(clock)
	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			cert := originalCert.DeepCopy()
			secret := originalSecret.DeepCopy()
			cr := originalCR
			if test.noSecret {
				secret = nil
			}
			if test.noCR {
				cr = nil
			}

			var diffCert, diffSecret string
			if test.c != nil {
				test.c((Cert)(cert))
				diffCert, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
					A:       difflib.SplitLines(spewConf.Sdump(originalCert)),
					B:       difflib.SplitLines(spewConf.Sdump(cert)),
					Context: 1,
				})
				if test.c != nil && diffCert == "" {
					t.Fatal("incorrect test case: the func to change the Certificate is non-nil but no change has been detected on the Certificate")
				}
			}
			if test.s != nil {
				test.s((*corev1.Secret)(secret))
				diffSec, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
					A:       difflib.SplitLines(spewConf.Sdump(originalSecret)),
					B:       difflib.SplitLines(spewConf.Sdump(secret)),
					Context: 1,
				})
				if test.s != nil && diffSec == "" {
					t.Fatal("incorrect test case: the func to change the Secret is non-nil but no change has been detected on the Secret")
				}
			}

			gotReason, gotMessage, gotReissue := policyChain.Evaluate(Input{
				Certificate:            cert,
				Secret:                 secret,
				CurrentRevisionRequest: cr,
			})

			if test.reissue != gotReissue {
				debug := ""
				if diffCert == "" {
					debug += "with no change to the Certificate"
				} else {
					debug += fmt.Sprintf("with the following changes to the Certificate : %s", diffCert)
				}
				if diffSecret == "" {
					debug += " and with no change to the Secret"
				} else {
					debug += fmt.Sprintf(" and with the following changes to the Secret : %s", diffSecret)
				}
				switch {
				case originalSecret == nil && originalCR == nil:
					debug += " and with neither the Secret nor the CertificateRequest available"
				case originalSecret != nil && originalCR == nil:
					debug += " and with only the Secret available (no CertificateRequest)"
				case originalSecret != nil && originalCR != nil:
					debug += " and with both the CertificateRequest and Secret available"
				case originalSecret == nil && originalCR != nil:
					t.Fatal("impossible test case: Secret not available but CertificateRequest is available")
				}

				reasonAndMessage := ", and the policyChain function did not return any explanatory reason nor message"
				if gotReason != "" && gotMessage != "" {
					reasonAndMessage = fmt.Sprintf(", reason: %s, message: %s", gotReason, gotMessage)
				}

				t.Errorf("%s, expected reissue=%v but got reissue=%v%s", debug, test.reissue, gotReissue, reasonAndMessage)
			}

			expectedReasonAndMessage := gotReason
			if gotMessage != "" {
				expectedReasonAndMessage += ": " + gotMessage
			}
			if test.msg != expectedReasonAndMessage {
				t.Errorf("the reason and message, of the form 'reason: message', was expected to be %q but got %q", test.msg, expectedReasonAndMessage)
			}
		})
	}
}

var spewConf = spew.ConfigState{
	Indent:                  " ",
	DisablePointerAddresses: true,
	DisableCapacities:       true,
	SortKeys:                true,
	DisableMethods:          true,
	MaxDepth:                10,
}
