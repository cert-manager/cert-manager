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
	"crypto/x509"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	testcr "github.com/jetstack/cert-manager/pkg/controller/certificaterequests/test"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/test/unit/gen"
	testlisters "github.com/jetstack/cert-manager/test/unit/listers"
)

func mustBuildOrder(t *testing.T, cr *v1alpha1.CertificateRequest,
	csr *x509.CertificateRequest) *v1alpha1.Order {
	order, err := buildOrder(cr, csr)
	if err != nil {
		t.Errorf("failed to build order during testing: %s", err)
		t.FailNow()
	}

	return order
}

func TestSign(t *testing.T) {
	rsaPK := testcr.GenerateRSAPrivateKey(t)
	csr, csrPEM := testcr.GenerateCSR(t, rsaPK)

	testCR := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestCSR(csrPEM),
		gen.SetCertificateRequestIsCA(true),
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
		gen.SetCertificateRequestIssuer(v1alpha1.ObjectReference{
			Name:  "acme-issuer",
			Group: certmanager.GroupName,
			Kind:  "Issuer",
		}),
	)

	_, rsaPEMCert := testcr.GenerateSelfSignedCertFromCR(t, testCR, rsaPK, time.Hour*24*60)
	testOrder := mustBuildOrder(t, testCR, csr)

	tests := map[string]testT{
		"a badly formed CSR should report failure": {
			issuer: gen.Issuer("acme-issuer"),
			certificateRequest: gen.CertificateRequestFrom(testCR,
				gen.SetCertificateRequestCSR([]byte("a bad csr")),
			),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					"Warning ErrorParsingCSR Failed to decode CSR in spec: error decoding certificate request PEM block",
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},

		//TODO: Think of a creative way to get `buildOrder` to fail :thinking_face:

		"if order doesn't exist then attempt to create one": {
			issuer:             gen.Issuer("acme-issuer"),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						v1alpha1.SchemeGroupVersion.WithResource("orders"),
						gen.DefaultTestNamespace,
						testOrder,
					)),
				},
				ExpectedEvents: []string{
					`Normal OrderCreated Created Order resource: default-unit-test-ns/test-cr-3958469914`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},

		"if we fail to get the order resource then we should report pending": {
			issuer:             gen.Issuer("acme-issuer"),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Normal ErrorGettingOrder Failed to get order resource default-unit-test-ns/test-cr-3958469914: this is a network error`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: true,
			FakeOrderLister: &testlisters.FakeOrderLister{
				OrdersFn: func(namespace string) cmlisters.OrderNamespaceLister {
					return &testlisters.FakeOrderNamespaceLister{
						GetFn: func(name string) (ret *v1alpha1.Order, err error) {
							return nil, errors.New("this is a network error")
						},
					}
				},
			},
		},

		"if the order resource is in a failed state then we should report failure": {
			issuer:             gen.Issuer("acme-issuer"),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Warning OrderFailed Failed to wait for order resource default-unit-test-ns/test-cr-3958469914 to become ready: order is in "invalid" state`,
				},
				CertManagerObjects: []runtime.Object{gen.OrderFrom(testOrder,
					gen.SetOrderState(v1alpha1.Invalid),
				)},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},

		"if the order is in an unknown, then report pending": {
			issuer:             gen.Issuer("acme-issuer"),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Normal OrderPending Waiting on certificate issuance from order default-unit-test-ns/test-cr-3958469914: order is currently pending: ""`,
				},
				CertManagerObjects: []runtime.Object{gen.OrderFrom(testOrder,
					gen.SetOrderState(""),
				)},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},

		"if the order is in Valid state then return the certificate as response": {
			issuer:             gen.Issuer("acme-issuer"),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				ExpectedEvents: []string{},
				CertManagerObjects: []runtime.Object{gen.OrderFrom(testOrder,
					gen.SetOrderState(v1alpha1.Valid),
					gen.SetOrderCertificate(rsaPEMCert),
				)},
				CheckFn: testcr.NoPrivateKeyCertificatesFieldsSetCheck(nil),
			},
			expectedErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

type testT struct {
	builder            *testpkg.Builder
	certificateRequest *v1alpha1.CertificateRequest
	issuer             v1alpha1.GenericIssuer

	checkFn     func(*testpkg.Builder, ...interface{})
	expectedErr bool

	FakeOrderLister *testlisters.FakeOrderLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Start()
	defer test.builder.Stop()

	a := NewACME(test.builder.Context)
	test.builder.Sync()

	if test.FakeOrderLister != nil {
		a.orderLister = test.FakeOrderLister
	}

	// Deep copy CertificateRequest to prevent carrying condition state across
	// multiple test cases from the same shared base CertificateRequest struct
	resp, err := a.Sign(context.Background(), test.certificateRequest.DeepCopy(), test.issuer)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}
	test.builder.CheckAndFinish(resp, err)
}
