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

package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"

	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
	testlisters "github.com/jetstack/cert-manager/test/unit/listers"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func generateCSR(t *testing.T, secretKey crypto.Signer) []byte {
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "test",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
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
	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerACME(cmapi.ACMEIssuer{}),
	)

	sk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	//skPEM := pki.EncodePKCS1PrivateKey(sk)
	csrPEM := generateCSR(t, sk)

	baseCR := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestCSR(csrPEM),
		gen.SetCertificateRequestIsCA(false),
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
		gen.SetCertificateRequestIssuer(cmapi.ObjectReference{
			Name:  baseIssuer.Name,
			Group: certmanager.GroupName,
			Kind:  "Issuer",
		}),
	)

	csr, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	template, err := pki.GenerateTemplateFromCertificateRequest(baseCR)
	if err != nil {
		t.Errorf("error generating template: %v", err)
	}

	certPEM, _, err := pki.SignCSRTemplate([]*x509.Certificate{template}, sk, template)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	baseOrder, err := buildOrder(baseCR, csr)
	if err != nil {
		t.Errorf("failed to build order during testing: %s", err)
		t.FailNow()
	}

	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	tests := map[string]testT{
		"a badly formed CSR should report failure": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestCSR([]byte("a bad csr")),
			),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning BadConfig Resource validation failed: spec.csr: Invalid value: []byte{0x61, 0x20, 0x62, 0x61, 0x64, 0x20, 0x63, 0x73, 0x72}: failed to decode csr: error decoding certificate request PEM block",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCSR([]byte("a bad csr")),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Resource validation failed: spec.csr: Invalid value: []byte{0x61, 0x20, 0x62, 0x61, 0x64, 0x20, 0x63, 0x73, 0x72}: failed to decode csr: error decoding certificate request PEM block",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},

		//TODO: Think of a creative way to get `buildOrder` to fail :thinking_face:

		"if order doesn't exist then attempt to create one": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal OrderCreated Created Order resource default-unit-test-ns/test-cr-1108683324",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						cmapi.SchemeGroupVersion.WithResource("orders"),
						gen.DefaultTestNamespace,
						baseOrder,
					)),
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Created Order resource default-unit-test-ns/test-cr-1108683324",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},

		"if we fail to get the order resource due to a transient error then we should report pending and return error to re-sync": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					"Normal OrderGetError Failed to get order resource default-unit-test-ns/test-cr-1108683324: this is a network error",
				},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to get order resource default-unit-test-ns/test-cr-1108683324: this is a network error",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeOrderLister: &testlisters.FakeOrderLister{
				OrdersFn: func(namespace string) cmlisters.OrderNamespaceLister {
					return &testlisters.FakeOrderNamespaceLister{
						GetFn: func(name string) (ret *cmapi.Order, err error) {
							return nil, errors.New("this is a network error")
						},
					}
				},
			},
			expectedErr: true,
		},

		"if the order resource is in a failed state then we should report failure": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Warning OrderFailed Failed to wait for order resource default-unit-test-ns/test-cr-1108683324 to become ready: order is in "invalid" state`,
				},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy(),
					gen.OrderFrom(baseOrder,
						gen.SetOrderState(cmapi.Invalid),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            `Failed to wait for order resource default-unit-test-ns/test-cr-1108683324 to become ready: order is in "invalid" state`,
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},

		"if the order is in an unknown state, then report pending": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Normal OrderPending Waiting on certificate issuance from order default-unit-test-ns/test-cr-1108683324: "pending"`,
				},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy(),
					gen.OrderFrom(baseOrder,
						gen.SetOrderState(cmapi.Pending),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Waiting on certificate issuance from order default-unit-test-ns/test-cr-1108683324: "pending"`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},

		"if the order is in Valid state then return the certificate as response": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				CertManagerObjects: []runtime.Object{gen.OrderFrom(baseOrder,
					gen.SetOrderState(cmapi.Valid),
					gen.SetOrderCertificate(certPEM),
				), baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
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
	builder            *testpkg.Builder
	certificateRequest *cmapi.CertificateRequest

	expectedErr bool

	fakeOrderLister *testlisters.FakeOrderLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Start()
	defer test.builder.Stop()

	ac := NewACME(test.builder.Context)
	if test.fakeOrderLister != nil {
		ac.orderLister = test.fakeOrderLister
	}

	test.builder.Sync()

	controller := certificaterequests.New(apiutil.IssuerACME, ac)
	controller.Register(test.builder.Context)
	test.builder.Sync()

	err := controller.Sync(context.Background(), test.certificateRequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}
