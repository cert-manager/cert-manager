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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/utils/clock"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	"github.com/cert-manager/cert-manager/internal/test/testutil"
	accountstest "github.com/cert-manager/cert-manager/pkg/acme/accounts/test"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/scheduler"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	acmeapi "github.com/cert-manager/cert-manager/third_party/forked/acme"
)

// policyEvaluatorBuilder returns a fake readyConditionFunc for ReadinessController.
func policyEvaluatorBuilder(c cmapi.CertificateCondition) policyEvaluatorFunc {
	return func(chain policies.Chain, input policies.Input) cmapi.CertificateCondition {
		return c
	}
}

// renewalTimeBuilder returns a fake renewalTimeFunc for ReadinessController.
func renewalTimeBuilder(rt *metav1.Time, err error) pki.RenewalTimeFunc {
	return func(notBefore, notAfter time.Time, renewBefore *metav1.Duration, renewBeforePercentage *int32, renewalSpec *cmapi.CertificateRenewal, opts ...pki.RenewalTimeOptions) (*metav1.Time, error) {
		return rt, err
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

		// renewalTimeError will be the error that should be returned from the renewal function
		renewalTimeError error

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
		"update status as not ready (Ready=False) with invalid renewal time": {
			condition: cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionReady,
				Status:             cmmeta.ConditionFalse,
				Reason:             policies.WindowError,
				Message:            "Could not calculate renewal time: cannot find a time with the given windows",
				LastTransitionTime: &metaNow,
			},
			cert:              gen.CertificateFrom(cert),
			certShouldUpdate:  true,
			secretShouldExist: true,
			notAfter:          func(m metav1.Time) *metav1.Time { return &m }(metav1.NewTime(now.Add(time.Hour * 2).Truncate(time.Second))),
			notBefore:         func(m metav1.Time) *metav1.Time { return &m }(metav1.NewTime(now.Truncate(time.Second))),
			renewalTime:       func() *metav1.Time { return nil }(),
			renewalTimeError:  fmt.Errorf("cannot find a time with the given windows"),
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
			w.controller.renewalTimeCalculator = renewalTimeBuilder(test.renewalTime, test.renewalTimeError)

			// Override controller's event recorder with a fake recorder to capture some events.
			w.controller.recorder = new(testpkg.FakeRecorder)

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
			err = w.controller.ProcessItem(t.Context(), key)
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
			message:        "Issuing certificate as Secret contains invalid private key data: error decoding private key PEM block: no PEM data was found in given input",
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
			message:        "Issuing certificate as Secret contains an invalid certificate: error decoding certificate PEM block: no valid certificates found",
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
					cmmeta.IssuerReference{Name: "testissuer", Kind: "IssuerKind", Group: "group.example.com"})),
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
					cmmeta.IssuerReference{
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
				gen.SetCertificateIssuer(cmmeta.IssuerReference{
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
				gen.SetCertificateRequestIssuer(cmmeta.IssuerReference{
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
				gen.SetCertificateIssuer(cmmeta.IssuerReference{
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
					cmmeta.IssuerReference{
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

func TestReadinessForARI(t *testing.T) {
	now := time.Now().UTC()
	metaNow := metav1.NewTime(now)
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
		Spec: cmapi.CertificateSpec{
			SecretName: "test-secret",
			DNSNames:   []string{"example.com"},
			IssuerRef: cmmeta.IssuerReference{
				Name:  "test-issuer",
				Kind:  cmapi.IssuerKind,
				Group: "cert-manager.io",
			},
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

		// renewalTimeError will be the error that should be returned from the renewal function
		renewalTimeError error

		wantsErr bool

		acmeClient acmecl.Interface

		issuer *cmapi.Issuer
	}{
		"update status for a Certificate that is evaluated as Ready with ARI and whose spec.secretName secret contains a valid X509 cert": {
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
			acmeClient: &acmecl.FakeACME{
				FakeGetRenewalInfo: func(ctx context.Context, cert *x509.Certificate) (*acmeapi.RenewalInfoResponse, error) {
					return &acmeapi.RenewalInfoResponse{
						SuggestedWindow: acmeapi.RenewalInfoWindow{
							Start: now.Add(24 * time.Hour),
							End:   now.Add(48 * time.Hour),
						},
						ExplanationURL: "example.com/explanation",
					}, nil
				},
			},
			issuer: gen.Issuer("test-issuer",
				gen.SetIssuerNamespace("testns"),
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					RenewalInformationSource: cmacme.ACMERenewalInformationSourceARI,
				}),
			),
		},
		"skip ARI if issuer has it disabled": {
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
			acmeClient: &acmecl.FakeACME{
				FakeGetRenewalInfo: func(ctx context.Context, cert *x509.Certificate) (*acmeapi.RenewalInfoResponse, error) {
					return &acmeapi.RenewalInfoResponse{
						SuggestedWindow: acmeapi.RenewalInfoWindow{
							Start: now.Add(24 * time.Hour),
							End:   now.Add(48 * time.Hour),
						},
						ExplanationURL: "example.com/explanation",
					}, nil
				},
			},
			issuer: gen.Issuer("test-issuer",
				gen.SetIssuerNamespace("testns"),
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					RenewalInformationSource: cmacme.ACMERenewalInformationSourceNone,
				}),
			),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Enable the ACMEUseARI feature gate so the readiness
			// controller exercises the ARI code path under test.
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultMutableFeatureGate, feature.ACMEUseARI, true)

			builder := &testpkg.Builder{
				T: t,
				// Fix the clock to be able to set lastTransitionTime on Certificate's Ready condition.
				Clock: fakeclock.NewFakeClock(now),
			}
			if test.cert != nil {
				// Ensures cert is loaded into the builder's fake clientset.
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.cert)
			}
			builder.CertManagerObjects = append(builder.CertManagerObjects, test.issuer)

			var leafCertID string
			if test.secretShouldExist {
				mods := make([]gen.SecretModifier, 0)
				// If the test scenario needs a secret with a valid X509 cert.
				if test.notBefore != nil && test.notAfter != nil {
					// The leaf must carry an AKI: without one no ARI CertID
					// can be computed and the controller clears the ACME
					// status entirely instead of fetching renewal info.
					leaf, certID := mustLeafWithAKI(t, test.notBefore.Time, test.notAfter.Time, 41)
					leafCertID = certID
					x509Bytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
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

			// Override controller's event recorder with a fake recorder to capture some events.
			w.controller.recorder = new(testpkg.FakeRecorder)

			w.controller.accountRegistry = &accountstest.FakeRegistry{
				GetClientFunc: func(uid string) (acmecl.Interface, error) {
					return test.acmeClient, nil
				},
			}

			var expectedRenewalTime *metav1.Time
			var ariInfo *acmeapi.RenewalInfoResponse
			if test.renewalTime != nil {
				expectedRenewalTime = test.renewalTime
			} else {
				ariInfo, _ = test.acmeClient.GetRenewalInfo(t.Context(), nil)
				// Pre-compute renewal time once. pki.RenewalTime selects a random
				// instant within the ARI SuggestedWindow, so we must compute the
				// expected value here and have the override return the same
				// deterministic value when invoked by the controller.
				expectedRenewalTime, err := pki.RenewalTime(test.notBefore.Time, test.notAfter.Time, nil, nil, nil, pki.WithARIInfo(ariInfo))
				if err != nil {
					t.Fatal(err)
				}

				if expectedRenewalTime.Time.Before(ariInfo.SuggestedWindow.Start) || expectedRenewalTime.After(ariInfo.SuggestedWindow.End) {
					t.Fatalf("expected renewal time %v to be within the ARI suggested window (%v - %v)", expectedRenewalTime, ariInfo.SuggestedWindow.Start, ariInfo.SuggestedWindow.End)
				}
			}

			w.controller.renewalTimeCalculator = func(t1, t2 time.Time, d *metav1.Duration, i *int32, cr *cmapi.CertificateRenewal, rto ...pki.RenewalTimeOptions) (*metav1.Time, error) {
				return expectedRenewalTime, nil
			}

			if test.certShouldUpdate {
				c := gen.CertificateFrom(test.cert,
					gen.SetCertificateStatusCondition(test.condition))

				// gen package functions don't accept pointers - we need to test setting these values to nil in some scenarios.
				c.Status.NotAfter = test.notAfter
				c.Status.NotBefore = test.notBefore
				c.Status.RenewalTime = expectedRenewalTime

				if ariInfo != nil {
					// Expected ACME ARI status populated by the controller
					// when ACMEUseARI is enabled. LastChecked is set to the
					// fake clock's "now" by the controller. NextCheck is
					// computed with random jitter so it is ignored in the
					// match below.
					c.Status.ACME = &cmapi.CertificateACMEStatus{
						ARI: &cmapi.CertificateACMEARIStatus{
							CertID:         leafCertID,
							ExplanationURL: ariInfo.ExplanationURL,
							SuggestedWindow: &cmapi.ACMERenewalWindow{
								Start: &metav1.Time{Time: ariInfo.SuggestedWindow.Start},
								End:   &metav1.Time{Time: ariInfo.SuggestedWindow.End},
							},
							LastChecked: &metaNow,
						},
					}
				}

				builder.ExpectedActions = append(builder.ExpectedActions,
					testpkg.NewCustomMatch(
						coretesting.NewUpdateSubresourceAction(
							cmapi.SchemeGroupVersion.WithResource("certificates"),
							"status",
							c.Namespace,
							c),
						func(expected, actual coretesting.Action) error {
							return testutil.Diff(expected, actual,
								cmp.FilterPath(func(p cmp.Path) bool {
									return p.Last().String() == ".ManagedFields"
								}, cmp.Ignore()),
								// NextCheck includes random jitter so cannot be deterministic.
								cmpopts.IgnoreFields(cmapi.CertificateACMEARIStatus{}, "NextCheck"),
							)
						},
					))
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
			err = w.controller.ProcessItem(t.Context(), key)
			if test.wantsErr != (err != nil) {
				t.Errorf("expected error: %v, got : %v", test.wantsErr, err)
			}

			if err := builder.AllActionsExecuted(); err != nil {
				builder.T.Error(err)
			}
		})
	}
}

// mustLeafWithAKI returns a leaf certificate signed by a throwaway CA, together
// with its ARI CertID.
func mustLeafWithAKI(t *testing.T, notBefore, notAfter time.Time, serial int64) (*x509.Certificate, string) {
	t.Helper()

	caPK, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		PublicKey:             caPK.Public(),
		IsCA:                  true,
	}
	_, caCert, err := pki.SignCertificate(caTmpl, caTmpl, caPK.Public(), caPK)
	if err != nil {
		t.Fatal(err)
	}

	leafPK, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey:    leafPK.Public(),
	}
	_, leaf, err := pki.SignCertificate(leafTmpl, caCert, leafPK.Public(), caPK)
	if err != nil {
		t.Fatal(err)
	}

	certID, err := acmeapi.CertificateARIID(leaf)
	if err != nil {
		t.Fatalf("test fixture leaf has no usable ARI CertID: %v", err)
	}
	return leaf, certID
}

// mustLeafWithoutAKI returns a self-signed, non-CA leaf. acmeapi.CertificateARIID
// cannot derive a CertID for it.
func mustLeafWithoutAKI(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	pk, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey:    pk.Public(),
	}
	_, leaf, err := pki.SignCertificate(tmpl, tmpl, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acmeapi.CertificateARIID(leaf); err == nil {
		t.Fatal("expected fixture leaf to have no usable ARI CertID")
	}
	return leaf
}

// TestUseARIForRenewalStaleness covers the decision of whether the ARI block in
// status still describes the certificate currently held in the Secret.
//
// See https://github.com/cert-manager/cert-manager/issues/8993.
func TestUseARIForRenewalStaleness(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	// ACME CAs backdate NotBefore (Let's Encrypt by an hour). Every fixture
	// here does the same, because backdating is what defeats a staleness check
	// based on comparing timestamps against NotBefore.
	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(89 * 24 * time.Hour)

	currentLeaf, currentCertID := mustLeafWithAKI(t, notBefore, notAfter, 2)
	_, previousCertID := mustLeafWithAKI(t, now.Add(-90*24*time.Hour), now.Add(time.Hour), 3)
	noAKILeaf := mustLeafWithoutAKI(t, notBefore, notAfter)

	// A window belonging to the *previous* certificate: it opened shortly
	// before the renewal that produced currentLeaf, so its start still falls
	// after currentLeaf's backdated NotBefore.
	staleWindow := &cmapi.ACMERenewalWindow{
		Start: &metav1.Time{Time: now.Add(-30 * time.Minute)},
		End:   &metav1.Time{Time: now.Add(-10 * time.Minute)},
	}
	if !staleWindow.Start.Time.After(notBefore) {
		t.Fatal("fixture error: stale window must start after the current cert's backdated NotBefore")
	}

	freshWindow := acmeapi.RenewalInfoWindow{
		Start: now.Add(24 * time.Hour),
		End:   now.Add(48 * time.Hour),
	}

	issuer := gen.Issuer("test-issuer",
		gen.SetIssuerNamespace("testns"),
		gen.SetIssuerACME(cmacme.ACMEIssuer{
			RenewalInformationSource: cmacme.ACMERenewalInformationSourceARI,
		}),
	)
	secret := gen.Secret("test-secret",
		gen.SetSecretNamespace("testns"),
		gen.SetSecretAnnotations(map[string]string{
			cmapi.IssuerNameAnnotationKey:  "test-issuer",
			cmapi.IssuerKindAnnotationKey:  cmapi.IssuerKind,
			cmapi.IssuerGroupAnnotationKey: "cert-manager.io",
		}),
	)

	tests := map[string]struct {
		leaf *x509.Certificate

		// ari is the pre-existing status.acme.ari block, if any.
		ari *cmapi.CertificateACMEARIStatus

		// fetchErr, when set, is returned by the fake GetRenewalInfo.
		fetchErr error

		wantFetches           int
		check                 func(t *testing.T, ari *cmapi.CertificateACMEARIStatus)
		wantACMEStatusCleared bool
	}{
		"fetches when no ARI information has been recorded yet": {
			leaf:        currentLeaf,
			wantFetches: 1,
			check: func(t *testing.T, ari *cmapi.CertificateACMEARIStatus) {
				if ari == nil {
					t.Fatal("expected an ARI status block to be populated")
				}
				if ari.CertID != currentCertID {
					t.Errorf("CertID = %q, want %q", ari.CertID, currentCertID)
				}
				if ari.SuggestedWindow == nil || !ari.SuggestedWindow.Start.Time.Equal(freshWindow.Start) {
					t.Errorf("SuggestedWindow = %v, want start %v", ari.SuggestedWindow, freshWindow.Start)
				}
			},
		},
		"does not refetch while the CertID matches and nextCheck is in the future": {
			leaf: currentLeaf,
			ari: &cmapi.CertificateACMEARIStatus{
				CertID:      currentCertID,
				NextCheck:   &metav1.Time{Time: now.Add(time.Hour)},
				LastChecked: &metav1.Time{Time: now.Add(-time.Minute)},
				SuggestedWindow: &cmapi.ACMERenewalWindow{
					Start: &metav1.Time{Time: freshWindow.Start},
					End:   &metav1.Time{Time: freshWindow.End},
				},
			},
			wantFetches: 0,
		},
		"refetches when the recorded CertID belongs to a previous certificate": {
			leaf: currentLeaf,
			ari: &cmapi.CertificateACMEARIStatus{
				CertID:          previousCertID,
				NextCheck:       &metav1.Time{Time: now.Add(time.Hour)},
				LastChecked:     &metav1.Time{Time: now.Add(-time.Minute)},
				SuggestedWindow: staleWindow,
			},
			wantFetches: 1,
			check: func(t *testing.T, ari *cmapi.CertificateACMEARIStatus) {
				if ari.CertID != currentCertID {
					t.Errorf("CertID = %q, want it restamped to %q", ari.CertID, currentCertID)
				}
				if ari.SuggestedWindow == nil || !ari.SuggestedWindow.Start.Time.Equal(freshWindow.Start) {
					t.Errorf("SuggestedWindow = %v, want it replaced with start %v", ari.SuggestedWindow, freshWindow.Start)
				}
			},
		},
		"refetches once nextCheck has elapsed": {
			leaf: currentLeaf,
			ari: &cmapi.CertificateACMEARIStatus{
				CertID:      currentCertID,
				NextCheck:   &metav1.Time{Time: now.Add(-time.Minute)},
				LastChecked: &metav1.Time{Time: now.Add(-6 * time.Hour)},
				SuggestedWindow: &cmapi.ACMERenewalWindow{
					Start: &metav1.Time{Time: freshWindow.Start},
					End:   &metav1.Time{Time: freshWindow.End},
				},
			},
			wantFetches: 1,
		},
		// A failed fetch must not leave a window describing a superseded
		// certificate next to a freshly bumped lastChecked - that is the
		// inconsistency reported in the issue.
		"a failed fetch does not leave a window from a previous certificate": {
			leaf: currentLeaf,
			ari: &cmapi.CertificateACMEARIStatus{
				CertID:          previousCertID,
				NextCheck:       &metav1.Time{Time: now.Add(time.Hour)},
				LastChecked:     &metav1.Time{Time: now.Add(-time.Minute)},
				SuggestedWindow: staleWindow,
			},
			fetchErr:    errors.New("simulated ARI fetch failure"),
			wantFetches: 1,
			check: func(t *testing.T, ari *cmapi.CertificateACMEARIStatus) {
				if ari.LastError == "" {
					t.Error("expected LastError to be recorded")
				}
				if ari.SuggestedWindow != nil {
					t.Errorf("SuggestedWindow = %v, want nil so status cannot contradict itself", ari.SuggestedWindow)
				}
			},
		},
		"clears the ARI info when the certificate has no usable CertID": {
			leaf: noAKILeaf,
			ari: &cmapi.CertificateACMEARIStatus{
				CertID:          currentCertID,
				NextCheck:       &metav1.Time{Time: now.Add(time.Hour)},
				LastChecked:     &metav1.Time{Time: now.Add(-time.Minute)},
				SuggestedWindow: staleWindow,
				ExplanationURL:  "https://example.com/why",
			},
			wantFetches:           0,
			wantACMEStatusCleared: true,
			check: func(t *testing.T, ari *cmapi.CertificateACMEARIStatus) {
				if ari != nil {
					t.Errorf("expected status.acme.ari to be cleared, got %v", ari)
				}
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultMutableFeatureGate, feature.ACMEUseARI, true)

			var fetches int
			acmeClient := &acmecl.FakeACME{
				FakeGetRenewalInfo: func(_ context.Context, _ *x509.Certificate) (*acmeapi.RenewalInfoResponse, error) {
					fetches++
					if test.fetchErr != nil {
						return nil, test.fetchErr
					}
					return &acmeapi.RenewalInfoResponse{
						SuggestedWindow: freshWindow,
						ExplanationURL:  "https://example.com/explanation",
						RetryAfter:      6 * time.Hour,
					}, nil
				},
			}

			builder := &testpkg.Builder{
				T:     t,
				Clock: fakeclock.NewFakeClock(now),
			}
			builder.CertManagerObjects = append(builder.CertManagerObjects, issuer)
			builder.KubeObjects = append(builder.KubeObjects, secret)
			builder.Init()
			defer builder.Stop()

			// Register before Start so the informers it requests are synced.
			w := &controllerWrapper{}
			if _, _, err := w.Register(builder.Context); err != nil {
				t.Fatal(err)
			}
			w.controller.recorder = new(testpkg.FakeRecorder)
			w.controller.accountRegistry = &accountstest.FakeRegistry{
				GetClientFunc: func(string) (acmecl.Interface, error) { return acmeClient, nil },
			}
			w.controller.renewalTimeCalculator = renewalTimeBuilder(&metav1.Time{Time: now.Add(24 * time.Hour)}, nil)

			builder.Start()

			crt := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Spec: cmapi.CertificateSpec{
					SecretName: "test-secret",
					DNSNames:   []string{"example.com"},
					IssuerRef: cmmeta.IssuerReference{
						Name:  "test-issuer",
						Kind:  cmapi.IssuerKind,
						Group: "cert-manager.io",
					},
				},
			}
			if test.ari != nil {
				crt.Status.ACME = &cmapi.CertificateACMEStatus{ARI: test.ari.DeepCopy()}
			}

			key := types.NamespacedName{Namespace: crt.Namespace, Name: crt.Name}
			w.controller.useARIForRenewal(t.Context(), crt, test.leaf, secret, key)

			if fetches != test.wantFetches {
				t.Errorf("GetRenewalInfo called %d times, want %d", fetches, test.wantFetches)
			}

			if test.check != nil {
				var got *cmapi.CertificateACMEARIStatus
				if crt.Status.ACME != nil {
					got = crt.Status.ACME.ARI
				}
				if got == nil && !test.wantACMEStatusCleared {
					t.Fatal("expected status.acme.ari to be present")
				}
				test.check(t, got)
			}
		})
	}
}

// TestARIRenewalTimeFromStatus covers the decision of whether the renewal time
// already recorded in status was derived from the ARI window of the certificate
// currently held in the Secret, and can therefore be kept instead of being
// overwritten by the plain renewBefore calculation.
func TestARIRenewalTimeFromStatus(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(89 * 24 * time.Hour)

	currentLeaf, currentCertID := mustLeafWithAKI(t, notBefore, notAfter, 11)
	_, previousCertID := mustLeafWithAKI(t, now.Add(-90*24*time.Hour), now.Add(time.Hour), 12)
	noAKILeaf := mustLeafWithoutAKI(t, notBefore, notAfter)

	windowStart := &metav1.Time{Time: now.Add(24 * time.Hour)}
	windowEnd := &metav1.Time{Time: now.Add(48 * time.Hour)}
	window := &cmapi.ACMERenewalWindow{Start: windowStart, End: windowEnd}
	inWindow := &metav1.Time{Time: now.Add(36 * time.Hour)}

	crt := func(ari *cmapi.CertificateACMEARIStatus, renewalTime *metav1.Time) *cmapi.Certificate {
		c := &cmapi.Certificate{}
		if ari != nil {
			c.Status.ACME = &cmapi.CertificateACMEStatus{ARI: ari}
		}
		c.Status.RenewalTime = renewalTime
		return c
	}

	tests := map[string]struct {
		crt  *cmapi.Certificate
		leaf *x509.Certificate
		want *metav1.Time
	}{
		"returns the stored renewal time when it falls inside the window of the current certificate": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{CertID: currentCertID, SuggestedWindow: window}, inWindow),
			leaf: currentLeaf,
			want: inWindow,
		},
		"nil when no ACME status has been recorded": {
			crt:  crt(nil, inWindow),
			leaf: currentLeaf,
		},
		"nil when no window has been recorded": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{CertID: currentCertID}, inWindow),
			leaf: currentLeaf,
		},
		"nil when the recorded window has no end": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{CertID: currentCertID, SuggestedWindow: &cmapi.ACMERenewalWindow{Start: windowStart}}, inWindow),
			leaf: currentLeaf,
		},
		"nil when no CertID has been recorded": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{SuggestedWindow: window}, inWindow),
			leaf: currentLeaf,
		},
		"nil when the recorded CertID belongs to a previous certificate": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{CertID: previousCertID, SuggestedWindow: window}, inWindow),
			leaf: currentLeaf,
		},
		"nil when the current certificate has no usable CertID": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{CertID: currentCertID, SuggestedWindow: window}, inWindow),
			leaf: noAKILeaf,
		},
		"nil when no renewal time has been recorded": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{CertID: currentCertID, SuggestedWindow: window}, nil),
			leaf: currentLeaf,
		},
		"nil when the stored renewal time is before the window opens": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{CertID: currentCertID, SuggestedWindow: window}, &metav1.Time{Time: now.Add(12 * time.Hour)}),
			leaf: currentLeaf,
		},
		"nil when the stored renewal time is after the window closes": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{CertID: currentCertID, SuggestedWindow: window}, &metav1.Time{Time: now.Add(72 * time.Hour)}),
			leaf: currentLeaf,
		},
		"nil when the stored renewal time does not postdate the certificate": {
			crt:  crt(&cmapi.CertificateACMEARIStatus{CertID: currentCertID, SuggestedWindow: window}, &metav1.Time{Time: notBefore}),
			leaf: currentLeaf,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := ariRenewalTimeFromStatus(test.crt, test.leaf)
			if (got == nil) != (test.want == nil) || (got != nil && !got.Time.Equal(test.want.Time)) {
				t.Errorf("ariRenewalTimeFromStatus() = %v, want %v", got, test.want)
			}
		})
	}
}

// TestProcessItemARIRenewalTimePersistence verifies that once the readiness
// controller has written an ARI-derived renewal time to status, the reconciles
// between ARI fetches keep it instead of overwriting it with the plain
// renewBefore calculation (which would bounce status.renewalTime on the
// re-enqueue that follows every ARI fetch).
func TestProcessItemARIRenewalTimePersistence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	metaNow := metav1.NewTime(now)

	leaf, leafCertID := mustLeafWithAKI(t, now.Add(-time.Hour), now.Add(89*24*time.Hour), 21)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	window := &cmapi.ACMERenewalWindow{
		Start: &metav1.Time{Time: now.Add(24 * time.Hour)},
		End:   &metav1.Time{Time: now.Add(48 * time.Hour)},
	}
	// The jittered pick the controller made inside the window on the reconcile
	// that fetched ARI.
	ariPickedTime := metav1.NewTime(now.Add(36 * time.Hour))
	calculatorTime := metav1.NewTime(now.Add(30 * 24 * time.Hour))

	readyCondition := cmapi.CertificateCondition{
		Type:               cmapi.CertificateConditionReady,
		Status:             cmmeta.ConditionTrue,
		Reason:             ReadyReason,
		Message:            "ready message",
		LastTransitionTime: &metaNow,
	}

	newCert := func(renewalTime *metav1.Time) *cmapi.Certificate {
		return &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
			Spec: cmapi.CertificateSpec{
				SecretName: "test-secret",
				DNSNames:   []string{"example.com"},
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  cmapi.IssuerKind,
					Group: "cert-manager.io",
				},
			},
			Status: cmapi.CertificateStatus{
				Conditions:  []cmapi.CertificateCondition{readyCondition},
				NotBefore:   &metav1.Time{Time: leaf.NotBefore},
				NotAfter:    &metav1.Time{Time: leaf.NotAfter},
				RenewalTime: renewalTime,
				ACME: &cmapi.CertificateACMEStatus{
					ARI: &cmapi.CertificateACMEARIStatus{
						CertID:          leafCertID,
						LastChecked:     &metav1.Time{Time: now.Add(-time.Hour)},
						NextCheck:       &metav1.Time{Time: now.Add(5 * time.Hour)},
						SuggestedWindow: window.DeepCopy(),
					},
				},
			},
		}
	}

	issuer := gen.Issuer("test-issuer",
		gen.SetIssuerNamespace("testns"),
		gen.SetIssuerACME(cmacme.ACMEIssuer{
			RenewalInformationSource: cmacme.ACMERenewalInformationSourceARI,
		}),
	)
	secret := gen.Secret("test-secret",
		gen.SetSecretNamespace("testns"),
		gen.SetSecretAnnotations(map[string]string{
			cmapi.IssuerNameAnnotationKey:  "test-issuer",
			cmapi.IssuerKindAnnotationKey:  cmapi.IssuerKind,
			cmapi.IssuerGroupAnnotationKey: "cert-manager.io",
		}),
		gen.SetSecretData(map[string][]byte{corev1.TLSCertKey: leafPEM}),
	)

	tests := map[string]struct {
		// renewalTime is status.renewalTime going into the reconcile.
		renewalTime *metav1.Time

		wantCalculatorCalls int

		// wantUpdatedRenewalTime, when set, is the renewal time expected in a
		// status update. When nil, no status update must happen at all.
		wantUpdatedRenewalTime *metav1.Time
	}{
		"keeps the ARI-derived renewal time between fetches without writing status": {
			renewalTime:         &ariPickedTime,
			wantCalculatorCalls: 0,
		},
		"recalculates when the stored renewal time falls outside the suggested window": {
			renewalTime:            &metav1.Time{Time: now.Add(72 * time.Hour)},
			wantCalculatorCalls:    1,
			wantUpdatedRenewalTime: &calculatorTime,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultMutableFeatureGate, feature.ACMEUseARI, true)

			crt := newCert(test.renewalTime)

			builder := &testpkg.Builder{
				T:                  t,
				Clock:              fakeclock.NewFakeClock(now),
				CertManagerObjects: []runtime.Object{crt, issuer},
				KubeObjects:        []runtime.Object{secret},
			}
			builder.Init()
			defer builder.Stop()

			// Register before Start so the informers it requests are synced.
			w := &controllerWrapper{}
			if _, _, err := w.Register(builder.Context); err != nil {
				t.Fatal(err)
			}
			w.controller.policyEvaluator = policyEvaluatorBuilder(readyCondition)
			w.controller.recorder = new(testpkg.FakeRecorder)
			w.controller.accountRegistry = &accountstest.FakeRegistry{
				GetClientFunc: func(string) (acmecl.Interface, error) {
					return &acmecl.FakeACME{
						FakeGetRenewalInfo: func(context.Context, *x509.Certificate) (*acmeapi.RenewalInfoResponse, error) {
							t.Error("GetRenewalInfo called; nextCheck is in the future and the CertID matches, so no fetch is expected")
							return nil, errors.New("unexpected ARI fetch")
						},
					}, nil
				},
			}
			var calculatorCalls int
			w.controller.renewalTimeCalculator = func(notBefore, notAfter time.Time, renewBefore *metav1.Duration, renewBeforePercentage *int32, renewalSpec *cmapi.CertificateRenewal, opts ...pki.RenewalTimeOptions) (*metav1.Time, error) {
				calculatorCalls++
				return &calculatorTime, nil
			}

			if test.wantUpdatedRenewalTime != nil {
				expCrt := newCert(test.wantUpdatedRenewalTime)
				builder.ExpectedActions = append(builder.ExpectedActions,
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						expCrt.Namespace,
						expCrt,
					)),
				)
			}

			builder.Start()

			key := types.NamespacedName{Namespace: crt.Namespace, Name: crt.Name}
			if err := w.controller.ProcessItem(t.Context(), key); err != nil {
				t.Fatalf("ProcessItem() error = %v", err)
			}

			if calculatorCalls != test.wantCalculatorCalls {
				t.Errorf("renewalTimeCalculator called %d times, want %d", calculatorCalls, test.wantCalculatorCalls)
			}
			// With no expected actions this also fails on any unexpected
			// status write - a reconcile between fetches must not touch the
			// Certificate at all.
			if err := builder.AllActionsExecuted(); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestScheduleRecheckAtExpiry drives a real ScheduledWorkQueue inside a
// synctest bubble, so the assertions are on when the re-check actually fires
// rather than on the delay that was requested.
func TestScheduleRecheckAtExpiry(t *testing.T) {
	key := types.NamespacedName{Namespace: "testns", Name: "test"}

	tests := map[string]struct {
		notAfter func(now time.Time) *metav1.Time
		// wantFireAfter is the offset from now at which the re-check must
		// fire. Zero means it must not fire at all.
		wantFireAfter time.Duration
	}{
		"fires one second after a future expiry": {
			notAfter:      func(now time.Time) *metav1.Time { return &metav1.Time{Time: now.Add(time.Hour)} },
			wantFireAfter: time.Hour + time.Second,
		},
		"does not fire for an already expired certificate": {
			notAfter: func(now time.Time) *metav1.Time { return &metav1.Time{Time: now.Add(-time.Hour)} },
		},
		"does not fire when the expiry is unknown": {
			notAfter: func(time.Time) *metav1.Time { return nil },
		},
		// time.Time.Sub saturates at math.MaxInt64 for a NotAfter this far
		// away. Whatever the arithmetic does with that, the re-check must
		// not fire early.
		"does not fire early for an expiry centuries away": {
			notAfter: func(time.Time) *metav1.Time {
				return &metav1.Time{Time: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)}
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()

				// The timer goroutine writes and the test goroutine reads, and
				// synctest.Wait does not order the two for the race detector.
				var mu sync.Mutex
				var fired []time.Duration
				firedAt := func() []time.Duration {
					mu.Lock()
					defer mu.Unlock()
					return append([]time.Duration(nil), fired...)
				}

				c := &controller{
					clock: clock.RealClock{},
					expiryWorkQueue: scheduler.NewScheduledWorkQueue(clock.RealClock{}, func(types.NamespacedName) {
						mu.Lock()
						defer mu.Unlock()
						fired = append(fired, time.Since(start))
					}),
				}
				defer c.expiryWorkQueue.Forget(key)

				c.scheduleRecheckAtExpiry(logr.Discard(), key, test.notAfter(start))

				if test.wantFireAfter == 0 {
					time.Sleep(100 * 365 * 24 * time.Hour)
					synctest.Wait()
					if got := firedAt(); len(got) != 0 {
						t.Fatalf("expected no re-check, but it fired at %v", got)
					}
					return
				}

				time.Sleep(test.wantFireAfter - time.Nanosecond)
				synctest.Wait()
				if got := firedAt(); len(got) != 0 {
					t.Fatalf("re-check fired early at %v", got)
				}

				time.Sleep(time.Nanosecond)
				synctest.Wait()
				if got := firedAt(); len(got) != 1 || got[0] != test.wantFireAfter {
					t.Fatalf("expected one re-check at %v, got %v", test.wantFireAfter, got)
				}
			})
		})
	}
}
