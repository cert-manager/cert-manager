/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package venafi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/Venafi/vcert/pkg/endpoint"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corelisters "k8s.io/client-go/listers/core/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	controllertest "github.com/jetstack/cert-manager/pkg/controller/test"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	internalvenafi "github.com/jetstack/cert-manager/pkg/internal/venafi"
	internalvenafifake "github.com/jetstack/cert-manager/pkg/internal/venafi/fake"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
	testlisters "github.com/jetstack/cert-manager/test/unit/listers"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func generateCSR(t *testing.T, secretKey crypto.Signer, alg x509.SignatureAlgorithm) []byte {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-common-name",
		},
		DNSNames: []string{
			"foo.example.com", "bar.example.com",
		},
		SignatureAlgorithm: alg,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, secretKey)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr
}

func TestSign(t *testing.T) {
	rsaSK, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csrPEM := generateCSR(t, rsaSK, x509.SHA1WithRSA)

	tppSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-tpp-secret",
		},
		Data: map[string][]byte{
			"username": []byte("test-username"),
			"password": []byte("test-password"),
		},
	}

	cloudSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cloud-secret",
		},
		Data: map[string][]byte{
			"api-key": []byte("test-api-key"),
		},
	}

	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
	)

	tppIssuer := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			TPP: &cmapi.VenafiTPP{
				CredentialsRef: cmapi.LocalObjectReference{
					Name: tppSecret.Name,
				},
			},
		}),
	)

	cloudIssuer := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			Cloud: &cmapi.VenafiCloud{
				APITokenSecretRef: cmapi.SecretKeySelector{
					LocalObjectReference: cmapi.LocalObjectReference{
						Name: cloudSecret.Name,
					},
				},
			},
		}),
	)

	baseCR := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestCSR(csrPEM),
	)

	tppCR := gen.CertificateRequestFrom(baseCR,
		gen.SetCertificateRequestIssuer(cmapi.ObjectReference{
			Group: certmanager.GroupName,
			Name:  tppIssuer.Name,
			Kind:  tppIssuer.Kind,
		}),
	)

	cloudCR := gen.CertificateRequestFrom(baseCR,
		gen.SetCertificateRequestIssuer(cmapi.ObjectReference{
			Group: certmanager.GroupName,
			Name:  cloudIssuer.Name,
			Kind:  cloudIssuer.Kind,
		}),
	)

	failGetSecretLister := &testlisters.FakeSecretLister{
		SecretsFn: func(namespace string) corelisters.SecretNamespaceLister {
			return &testlisters.FakeSecretNamespaceLister{
				GetFn: func(name string) (ret *corev1.Secret, err error) {
					return nil, errors.New("this is a network error")
				},
			}
		},
	}

	template, err := pki.GenerateTemplateFromCertificateRequest(baseCR)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	certPEM, _, err := pki.SignCertificate(template, template, rsaSK.Public(), rsaSK)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	clientReturnsPending := &internalvenafifake.Venafi{
		SignFn: func([]byte, time.Duration) ([]byte, error) {
			return nil, endpoint.ErrCertificatePending{
				CertificateID: "test-cert-id",
				Status:        "test-status-pending",
			}
		},
	}
	clientReturnsTimeout := &internalvenafifake.Venafi{
		SignFn: func([]byte, time.Duration) ([]byte, error) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{
				CertificateID: "test-cert-id",
			}
		},
	}
	clientReturnsGenericError := &internalvenafifake.Venafi{
		SignFn: func([]byte, time.Duration) ([]byte, error) {
			return nil, errors.New("this is an error")
		},
	}
	clientReturnsCert := &internalvenafifake.Venafi{
		SignFn: func([]byte, time.Duration) ([]byte, error) {
			return certPEM, nil
		},
	}

	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	tests := map[string]testT{
		"tpp: if fail to build client based on missing secret then return nil and hard fail": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal SecretMissing Required secret resource not found: secret "test-tpp-secret" not found`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Required secret resource not found: secret "test-tpp-secret" not found`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"tpp: if fail to build client based on secret lister transient error then return err and set pending": {
			certificateRequest: tppCR.DeepCopy(),
			issuer:             tppIssuer,
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal VenafiInitError Failed to initialise venafi client for signing: this is a network error`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to initialise venafi client for signing: this is a network error",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			expectedErr:      true,
		},
		"cloud: if fail to build client based on missing secret then return nil and hard fail": {
			certificateRequest: cloudCR.DeepCopy(),
			issuer:             cloudIssuer,
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal SecretMissing Required secret resource not found: secret "test-cloud-secret" not found`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Required secret resource not found: secret "test-cloud-secret" not found`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"cloud: if fail to build client based on secret lister transient error then return err and set pending": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal VenafiInitError Failed to initialise venafi client for signing: this is a network error`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to initialise venafi client for signing: this is a network error",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			expectedErr:      true,
		},
		"tpp: if sign returns pending error then set pending and return err": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{tppSecret},
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal IssuancePending Venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsPending,
			expectedErr:      true,
		},
		"cloud: if sign returns pending error then set pending and return err": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{cloudSecret},
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal IssuancePending Venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsPending,
			expectedErr:      true,
		},
		"tpp: if sign returns timeout error then set failed and return nil": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), tppIssuer.DeepCopy()},
				KubeObjects:        []runtime.Object{tppSecret},
				ExpectedEvents: []string{
					"Warning Timeout Timed out waiting for venafi certificate, the request will be retried: Operation timed out. You may try retrieving the certificate later using Pickup ID: test-cert-id",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Timed out waiting for venafi certificate, the request will be retried: Operation timed out. You may try retrieving the certificate later using Pickup ID: test-cert-id",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsTimeout,
		},
		"cloud: if sign returns timeout error then set failed and return nil": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{cloudSecret},
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning Timeout Timed out waiting for venafi certificate, the request will be retried: Operation timed out. You may try retrieving the certificate later using Pickup ID: test-cert-id",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Timed out waiting for venafi certificate, the request will be retried: Operation timed out. You may try retrieving the certificate later using Pickup ID: test-cert-id",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsTimeout,
		},
		"tpp: if sign returns generic error then set pending and return error": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{tppSecret},
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning RetrieveError Failed to obtain venafi certificate: this is an error",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Failed to obtain venafi certificate: this is an error",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsGenericError,
			expectedErr:      true,
		},
		"cloud: if sign returns generic error then set pending and return error": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{cloudSecret},
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning RetrieveError Failed to obtain venafi certificate: this is an error",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Failed to obtain venafi certificate: this is an error",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsGenericError,
			expectedErr:      true,
		},
		"tpp: if sign returns cert then return cert and not failed": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{tppSecret},
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(certPEM),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsCert,
		},
		"cloud: if sign returns cert then return cert and not failed": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{cloudSecret},
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(certPEM),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsCert,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock
			runTest(t, test)
		})
	}
}

type testT struct {
	builder            *controllertest.Builder
	certificateRequest *cmapi.CertificateRequest
	issuer             cmapi.GenericIssuer

	fakeClient *internalvenafifake.Venafi

	expectedErr bool

	fakeSecretLister *testlisters.FakeSecretLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	v := NewVenafi(test.builder.Context)

	if test.fakeSecretLister != nil {
		v.secretsLister = test.fakeSecretLister
	}

	if test.fakeClient != nil {
		v.clientBuilder = func(namespace string, secretsLister corelisters.SecretLister,
			issuer cmapi.GenericIssuer) (internalvenafi.Interface, error) {
			return test.fakeClient, nil
		}
	}

	controller := certificaterequests.New(apiutil.IssuerVenafi, v)
	controller.Register(test.builder.Context)
	test.builder.Start()

	// Deep copy the certificate request to prevent pulling condition state across tests
	err := controller.Sync(context.Background(), test.certificateRequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}
