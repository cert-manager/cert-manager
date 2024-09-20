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

package readiness

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// policyEvaluatorBuilder returns a fake readyConditionFunc for ReadinessController.
func policyEvaluatorBuilder(c cmapi.CertificateCondition) policyEvaluatorFunc {
	return func(chain policies.Chain, input policies.Input) cmapi.CertificateCondition {
		return c
	}
}

// renewalTimeBuilder returns a fake renewalTimeFunc for ReadinessController.
func renewalTimeBuilder(rt *metav1.Time) pki.RenewalTimeFunc {
	return func(notBefore, notAfter time.Time, renewBefore *metav1.Duration, renewBeforePercentage *int32) *metav1.Time {
		return rt
	}
}

func TestProcessItem(t *testing.T) {
	// now time is the current UTC time at the start of the test
	now := time.Now().UTC()
	metaNow := metav1.NewTime(now)
	// private key to be used to generate X509 certificate
	privKey := testcrypto.MustCreatePEMPrivateKey(t)
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
		Spec: cmapi.CertificateSpec{
			SecretName: "test-secret",
			DNSNames:   []string{"example.com"},
		},
	}
	// base Secret to be used in tests
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "testns",
			Name:      "test-secret",
		},
	}
	tests := map[string]struct {
		// key that should be passed to ProcessItem.
		// if not set, the 'namespace/name' of the 'Certificate' field will be used.
		// if neither is set, the key will be "".
		key types.NamespacedName

		// cert to be loaded to fake clientset
		cert *cmapi.Certificate

		// whether we expect an update action against the Certificate
		certShouldUpdate bool

		// Certificate's Ready condition to be applied with the update
		condition cmapi.CertificateCondition

		// whether secret should be loaded into the fake clientset
		// if notAfter, notBefore and renewalTime are set, an X509 cert will also be built and
		// added as tls.crt value to the secret data
		secretShouldExist bool

		// notAfter will be used to build the X509 cert and
		// as the updated Certificate's status.notAfter
		notAfter *metav1.Time

		// notBefore will be used to build the X509 cert and
		// as the updated Certificate's status.notBefore
		notBefore *metav1.Time

		// renewalTime will be the updated Certificate's status.renewalTime
		renewalTime *metav1.Time

		wantsErr bool
	}{
		"do nothing if an empty 'key' is used": {},
		"do nothing if an invalid 'key' is used": {
			key: types.NamespacedName{
				Namespace: "abc",
				Name:      "def/ghi",
			},
		},
		"do nothing if a key references a Certificate that does not exist": {
			key: types.NamespacedName{
				Namespace: "namespace",
				Name:      "name",
			},
		},
		"update status for a Certificate that is evaluated as Ready and whose spec.secretName secret contains a valid X509 cert": {
			condition: cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionReady,
				Status:             cmmeta.ConditionTrue,
				Reason:             ReadyReason,
				Message:            "ready message",
				LastTransitionTime: &metaNow,
			},
			cert:              gen.CertificateFrom(cert),
			certShouldUpdate:  true,
			secretShouldExist: true,
			notAfter:          func(m metav1.Time) *metav1.Time { return &m }(metav1.NewTime(now.Add(time.Hour * 2).Truncate(time.Second))),
			notBefore:         func(m metav1.Time) *metav1.Time { return &m }(metav1.NewTime(now.Truncate(time.Second))),
			renewalTime:       func(m metav1.Time) *metav1.Time { return &m }(metav1.NewTime(now.Add(time.Hour))),
		},
		"update status for a Certificate that is evaluated as not Ready and whose spec.secretName secret contains a valid X509 cert": {
			condition: cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionReady,
				Status:             cmmeta.ConditionFalse,
				Reason:             "some reason",
				Message:            "some message",
				LastTransitionTime: &metaNow,
			},
			cert:              gen.CertificateFrom(cert),
			certShouldUpdate:  true,
			secretShouldExist: true,
			notAfter:          func(m metav1.Time) *metav1.Time { return &m }(metav1.NewTime(now.Add(time.Hour * 2).Truncate(time.Second))),
			notBefore:         func(m metav1.Time) *metav1.Time { return &m }(metav1.NewTime(now.Truncate(time.Second))),
			renewalTime:       func(m metav1.Time) *metav1.Time { return &m }(metav1.NewTime(now.Add(time.Hour))),
		},
		"update status for a Certificate whose spec.secretName secret does not exist": {
			condition: cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionReady,
				Status:             cmmeta.ConditionFalse,
				Reason:             "some reason",
				Message:            "some message",
				LastTransitionTime: &metaNow,
			},
			cert: gen.CertificateFrom(cert),

			certShouldUpdate: true,
		},
		"update status for a Certificate whose spec.secretName secret does not contain a TLS certificate": {
			condition: cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionReady,
				Status:             cmmeta.ConditionFalse,
				Reason:             "some reason",
				Message:            "some message",
				LastTransitionTime: &metaNow,
			},
			cert:              gen.CertificateFrom(cert),
			certShouldUpdate:  true,
			secretShouldExist: true,
		},
		"update status for a Certificate that currently has Ready condition false, but policy evaluates to True": {
			condition: cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionReady,
				Status:             cmmeta.ConditionTrue,
				Reason:             ReadyReason,
				Message:            "ready message",
				LastTransitionTime: &metaNow,
			},
			cert: gen.CertificateFrom(cert, gen.SetCertificateStatusCondition(
				cmapi.CertificateCondition{
					Type:    cmapi.CertificateConditionReady,
					Status:  cmmeta.ConditionFalse,
					Reason:  "some reason",
					Message: "some message",
				})),
			certShouldUpdate:  true,
			secretShouldExist: true,
		},
		"update status for a Certificate that already has some other condition": {
			condition: cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionReady,
				Status:             cmmeta.ConditionFalse,
				Reason:             "some reason",
				Message:            "some message",
				LastTransitionTime: &metaNow,
			},
			cert: gen.CertificateFrom(cert, gen.SetCertificateStatusCondition(
				cmapi.CertificateCondition{
					Type:    cmapi.CertificateConditionIssuing,
					Status:  cmmeta.ConditionTrue,
					Reason:  "some reason",
					Message: "some message",
				})),
			certShouldUpdate: true,
		},
		"update status for a Certificate that has Ready condition set to true, but policy evaluator fails": {
			certShouldUpdate: true,
			condition: cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionReady,
				Status:             cmmeta.ConditionFalse,
				Reason:             "some reason",
				Message:            "some message",
				LastTransitionTime: &metaNow,
			},
			cert: gen.CertificateFrom(cert, gen.SetCertificateStatusCondition(
				cmapi.CertificateCondition{
					Type:    cmapi.CertificateConditionReady,
					Status:  cmmeta.ConditionTrue,
					Reason:  ReadyReason,
					Message: "ready message",
				})),
		},
		"update status for a Certificate that has a Ready condition and the policy evaluates to True - should remain True": {
			condition: cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionReady,
				Status:             cmmeta.ConditionTrue,
				Reason:             ReadyReason,
				Message:            "ready message",
				LastTransitionTime: &metaNow,
			},
			cert: gen.CertificateFrom(cert, gen.SetCertificateStatusCondition(
				cmapi.CertificateCondition{
					Type:               cmapi.CertificateConditionReady,
					Status:             cmmeta.ConditionTrue,
					Reason:             ReadyReason,
					Message:            "ready message",
					LastTransitionTime: &metaNow,
				})),
			secretShouldExist: true,
			certShouldUpdate:  false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create and initialise a new unit test builder.
			builder := &testpkg.Builder{
				T: t,
				// Fix the clock to be able to set lastTransitionTime on Certificate's Ready condition.
				Clock: fakeclock.NewFakeClock(now),
			}
			if test.cert != nil {
				// Ensures cert is loaded into the builder's fake clientset.
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.cert)
			}

			if test.secretShouldExist {
				mods := make([]gen.SecretModifier, 0)
				// If the test scenario needs a secret with a valid X509 cert.
				if test.notBefore != nil && test.notAfter != nil {
					x509Bytes := testcrypto.MustCreateCertWithNotBeforeAfter(t, privKey, cert, test.notBefore.Time, test.notAfter.Time)
					mods = append(mods,
						gen.SetSecretData(map[string][]byte{
							"tls.crt": x509Bytes,
						}))
				}
				// Ensure secret is loaded into the builder's fake clientset.
				builder.KubeObjects = append(builder.KubeObjects,
					gen.SecretFrom(secret, mods...))
			}

			builder.Init()

			// Register informers used by the controller using the registration wrapper.
			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}

			// Override controller's readyCondition func with a fake that returns test.condition.
			w.controller.policyEvaluator = policyEvaluatorBuilder(test.condition)

			// Override controller's renewalTime func with a fake that returns test.renewalTime.
			w.controller.renewalTimeCalculator = renewalTimeBuilder(test.renewalTime)

			// If Certificate's status should be updated,
			// build the expected Certificate and use it to set the expected update action on builder.
			if test.certShouldUpdate {
				c := gen.CertificateFrom(test.cert,
					gen.SetCertificateStatusCondition(test.condition))

				// gen package functions don't accept pointers - we need to test setting these values to nil in some scenarios.
				c.Status.NotAfter = test.notAfter
				c.Status.NotBefore = test.notBefore
				c.Status.RenewalTime = test.renewalTime

				builder.ExpectedActions = append(builder.ExpectedActions,
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						c.Namespace,
						c)))
			}

			// Start the informers and begin processing updates.
			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == (types.NamespacedName{}) && cert != nil {
				key = types.NamespacedName{
					Name:      cert.Name,
					Namespace: cert.Namespace,
				}
			}

			// Call ProcessItem
			err = w.controller.ProcessItem(context.Background(), key)
			if test.wantsErr != (err != nil) {
				t.Errorf("expected error: %v, got : %v", test.wantsErr, err)
			}

			if err := builder.AllActionsExecuted(); err != nil {
				builder.T.Error(err)
			}
		})
	}
}

// Test the evaluation of the ordered policy chain as a whole.
func TestNewReadinessPolicyChain(t *testing.T) {
	clock := &fakeclock.FakeClock{}
	privKey := testcrypto.MustCreatePEMPrivateKey(t)
	tests := map[string]struct {
		// policy inputs
		cert   *cmapi.Certificate
		cr     *cmapi.CertificateRequest
		secret *corev1.Secret

		// expected outputs
		reason, message string
		violationFound  bool
	}{
		"Certificate not Ready if Secret is missing": {
			cert:           gen.Certificate("test", gen.SetCertificateSecretName("something")),
			reason:         policies.DoesNotExist,
			message:        "Issuing certificate as Secret does not exist",
			violationFound: true,
		},
		"Certificate not Ready as Secret does not contain any data": {
			cert:           gen.Certificate("test", gen.SetCertificateSecretName("something")),
			secret:         gen.Secret("something"),
			reason:         policies.MissingData,
			message:        "Issuing certificate as Secret does not contain any data",
			violationFound: true,
		},
		"Certificate not Ready as Secret is missing private key": {
			cert:           gen.Certificate("test", gen.SetCertificateSecretName("something")),
			secret:         gen.Secret("something", gen.SetSecretData(map[string][]byte{corev1.TLSCertKey: []byte("test")})),
			reason:         policies.MissingData,
			message:        "Issuing certificate as Secret does not contain a private key",
			violationFound: true,
		},
		"Certificate not Ready as Secret is missing certificate": {
			cert:           gen.Certificate("test", gen.SetCertificateSecretName("something")),
			secret:         gen.Secret("something", gen.SetSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: []byte("test")})),
			reason:         policies.MissingData,
			message:        "Issuing certificate as Secret does not contain a certificate",
			violationFound: true,
		},
		"Certificate not Ready as Secret contains corrupt private key and certificate data": {
			cert: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: gen.Secret("something", gen.SetSecretData(
				map[string][]byte{
					corev1.TLSPrivateKeyKey: []byte("test"),
					corev1.TLSCertKey:       []byte("test"),
				})),
			reason:         policies.InvalidKeyPair,
			message:        "Issuing certificate as Secret contains invalid private key data: error decoding private key PEM block",
			violationFound: true,
		},
		"Certificate not Ready as Secret contains corrupt certificate data": {
			cert: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: gen.Secret("something", gen.SetSecretData(
				map[string][]byte{
					corev1.TLSPrivateKeyKey: privKey,
					corev1.TLSCertKey:       []byte("test"),
				})),
			reason:         policies.InvalidCertificate,
			message:        "Issuing certificate as Secret contains an invalid certificate: error decoding certificate PEM block",
			violationFound: true,
		},
		"Certificate not Ready as Secret contains a non-matching key-pair": {
			cert: &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "something"}},
			secret: gen.Secret("something", gen.SetSecretData(
				map[string][]byte{
					corev1.TLSPrivateKeyKey: privKey,
					// generate a different private key
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, testcrypto.MustCreatePEMPrivateKey(t),
						gen.Certificate("something else", gen.SetCertificateCommonName("example.com"))),
				})),
			reason:         policies.InvalidKeyPair,
			message:        "Issuing certificate as Secret contains a private key that does not match the certificate",
			violationFound: true,
		},
		"Certificate not Ready when CertificateRequest does not match certificate spec": {
			cert: gen.Certificate("something",
				gen.SetCertificateCommonName("new.example.com"),
				gen.SetCertificateIssuer(
					cmmeta.ObjectReference{Name: "testissuer", Kind: "IssuerKind", Group: "group.example.com"})),
			secret: gen.Secret("something",
				gen.SetSecretAnnotations(
					map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
				),
				gen.SetSecretData(
					map[string][]byte{
						corev1.TLSPrivateKeyKey: privKey,
						corev1.TLSCertKey: testcrypto.MustCreateCert(t, privKey,
							gen.Certificate("something else", gen.SetCertificateCommonName("old.example.com"))),
					},
				),
			),
			cr: gen.CertificateRequest("something",
				gen.SetCertificateRequestIssuer(
					cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
				),
				gen.SetCertificateRequestCSR(
					testcrypto.MustGenerateCSRImpl(t, privKey,
						gen.Certificate("somethingelse",
							gen.SetCertificateCommonName("old.example.com"))))),
			reason:         policies.RequestChanged,
			message:        "Fields on existing CertificateRequest resource not up to date: [spec.commonName]",
			violationFound: true,
		},
		"Certificate is not Ready when it has expired": {
			cert: gen.Certificate("something",
				gen.SetCertificateCommonName("new.example.com"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				})),
			secret: gen.Secret("something",
				gen.SetSecretAnnotations(map[string]string{
					cmapi.IssuerNameAnnotationKey:  "testissuer",
					cmapi.IssuerKindAnnotationKey:  "IssuerKind",
					cmapi.IssuerGroupAnnotationKey: "group.example.com",
				}),
				gen.SetSecretData(
					map[string][]byte{
						corev1.TLSPrivateKeyKey: privKey,
						corev1.TLSCertKey: testcrypto.MustCreateCertWithNotBeforeAfter(t, privKey,
							gen.Certificate("something", gen.SetCertificateCommonName("new.example.com")),
							clock.Now().Add(-3*time.Hour), clock.Now().Add(-1*time.Hour),
						),
					},
				)),
			cr: gen.CertificateRequest("something",
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				}),
				gen.SetCertificateRequestCSR(testcrypto.MustGenerateCSRImpl(t, privKey,
					gen.Certificate("something",
						gen.SetCertificateCommonName("new.example.com")))),
			),
			reason:         policies.Expired,
			message:        "Certificate expired on Sun, 31 Dec 0000 23:00:00 UTC",
			violationFound: true,
		},
		"Certificate is Ready, no policy violations found": {
			cert: gen.Certificate("something",
				gen.SetCertificateCommonName("new.example.com"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{
					Name:  "testissuer",
					Kind:  "IssuerKind",
					Group: "group.example.com",
				})),
			secret: gen.Secret("something",
				gen.SetSecretAnnotations(
					map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					}),
				gen.SetSecretData(
					map[string][]byte{
						corev1.TLSPrivateKeyKey: privKey,
						corev1.TLSCertKey: testcrypto.MustCreateCertWithNotBeforeAfter(t, privKey,
							&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "new.example.com"}},
							clock.Now(), clock.Now().Add(time.Hour*3),
						),
					},
				)),
			cr: gen.CertificateRequest("something",
				gen.SetCertificateRequestIssuer(
					cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
				),
				gen.SetCertificateRequestCSR(testcrypto.MustGenerateCSRImpl(t, privKey,
					gen.Certificate("something",
						gen.SetCertificateCommonName("new.example.com")))),
			),
			reason:  "",
			message: "",
		},
	}
	policyChain := policies.NewReadinessPolicyChain(clock)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			reason, message, violationFound := policyChain.Evaluate(policies.Input{
				Certificate:            test.cert,
				CurrentRevisionRequest: test.cr,
				Secret:                 test.secret,
			})
			if test.reason != reason {
				t.Errorf("unexpected 'reason' exp=%s, got=%s", test.reason, reason)
			}
			if test.message != message {
				t.Errorf("unexpected 'message' exp=%s, got=%s", test.message, message)
			}
			if test.violationFound != violationFound {
				t.Errorf("unexpected 'violationFound' exp=%v, got=%v", test.violationFound, violationFound)
			}
		})
	}
}
