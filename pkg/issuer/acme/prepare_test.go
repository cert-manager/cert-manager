package acme

import (
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
)

func TestPrepare(t *testing.T) {
	const generateNameSuffix = "test"
	stringGenerator := testpkg.FixedString(generateNameSuffix)
	testCert := &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "testcrt", Namespace: "default"},
		Spec: v1alpha1.CertificateSpec{
			CommonName: "test.com",
			ACME: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains:      []string{"test.com"},
						SolverConfig: v1alpha1.SolverConfig{HTTP01: &v1alpha1.HTTP01SolverConfig{}},
					},
				},
			},
		},
	}

	invalidTestCert := testCert.DeepCopy()
	invalidTestCert.Spec.CommonName = "test2.com"

	testCertOrderRefSet := testCert.DeepCopy()
	testCertOrderRefSet.Status.ACMEStatus().OrderRef = &v1alpha1.LocalObjectReference{
		Name: "testcrt-" + generateNameSuffix,
	}

	recentlyFailedCertificate := testCertOrderRefSet.DeepCopy()
	nowTime := metav1.NewTime(time.Now())
	recentlyFailedCertificate.Status.LastFailureTime = &nowTime

	notRecentlyFailedCertificate := testCertOrderRefSet.DeepCopy()
	pastTime := metav1.NewTime(time.Now().Add(time.Hour * -24))
	notRecentlyFailedCertificate.Status.LastFailureTime = &pastTime

	testOrder := buildOrder(testCert)
	testOrder.Name = testCertOrderRefSet.Status.ACMEStatus().OrderRef.Name
	readyTestOrder := testOrder.DeepCopy()
	readyTestOrder.Status.State = v1alpha1.Ready
	failedTestOrder := testOrder.DeepCopy()
	failedTestOrder.Status.State = v1alpha1.Failed
	invalidTestOrder := buildOrder(invalidTestCert)
	invalidTestOrder.Name = testCertOrderRefSet.Status.ACMEStatus().OrderRef.Name

	tests := map[string]acmeFixture{
		// Success cases
		"should not return an error if the existing order is in a 'ready' state": {
			Certificate: testCertOrderRefSet,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{readyTestOrder},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				if !reflect.DeepEqual(returnedCert, s.Certificate) {
					t.Errorf("expected %+v to equal %+v", returnedCert, s.Certificate)
				}
			},
			Err: false,
		},
		"should create an order and update the Certificate status if no existing order is named in status": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				ExpectedActions: []coretesting.Action{
					coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, testOrder),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				if returnedCert.Status.ACMEStatus().OrderRef.Name != testOrder.Name {
					t.Errorf("Expected orderRef.name to equal %q, but it is %q", testOrder.Name, returnedCert.Status.ACMEStatus().OrderRef.Name)
				}
			},
			Err: true,
		},
		"should create a new order and update Certificate status if the one referenced no longer exists": {
			Certificate: testCertOrderRefSet,
			Builder: &testpkg.Builder{
				ExpectedActions: []coretesting.Action{
					coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, testOrder),
				},
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				if returnedCert.Status.ACMEStatus().OrderRef.Name != testOrder.Name {
					t.Errorf("Expected orderRef.name to equal %q, but it is %q", testOrder.Name, returnedCert.Status.ACMEStatus().OrderRef.Name)
				}
			},
			Err: true,
		},
		"should delete the existing order, create a new one and update status if the order hash has changed": {
			Certificate: testCertOrderRefSet,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{invalidTestOrder},
				// create an Order based on a different version of the test cert
				ExpectedActions: []coretesting.Action{
					coretesting.NewDeleteAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), invalidTestOrder.Namespace, invalidTestOrder.Name),
					coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, buildOrder(testCert)),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
				s.FakeCMClient().PrependReactor("delete", "orders",
					s.EnsureReactorCalled("existing order deleted",
						testpkg.ObjectDeletedReactor(t, s.Builder, invalidTestOrder)),
				)
				s.FakeCMClient().PrependReactor("create", "orders",
					s.EnsureReactorCalled("new order created",
						testpkg.ObjectCreatedReactor(t, s.Builder, buildOrder(testCert))),
				)
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
			},
			Err: true,
		},
		// Failure cases
		"should set failure time and error if the referenced order has failed and last failure is not set": {
			Certificate: testCertOrderRefSet,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{failedTestOrder},
				// create an Order based on a different version of the test cert
				ExpectedActions: []coretesting.Action{},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				if returnedCert.Status.LastFailureTime == nil {
					t.Errorf("expected lastFailureTime to be set")
				}
			},
			Err: true,
		},
		"should not set failure time, but return error if the referenced order has failed and last failure < failureBackoffPeriod ago": {
			Certificate: recentlyFailedCertificate,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{failedTestOrder},
				// create an Order based on a different version of the test cert
				ExpectedActions: []coretesting.Action{},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				if !returnedCert.Status.LastFailureTime.Equal(recentlyFailedCertificate.Status.LastFailureTime) {
					t.Errorf("Expected status.lastFailureTime to equal %q, but it is %q", recentlyFailedCertificate.Status.LastFailureTime, returnedCert.Status.LastFailureTime)
				}
			},
			Err: true,
		},
		"should clear failure time and create a new order if the lastFailureTime > failureBackoffPeriod minutes ago": {
			Certificate: notRecentlyFailedCertificate,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{failedTestOrder},
				// create an Order based on a different version of the test cert
				ExpectedActions: []coretesting.Action{
					coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, buildOrder(testCert)),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
				s.FakeCMClient().PrependReactor("create", "orders",
					s.EnsureReactorCalled("new order created",
						testpkg.ObjectCreatedReactor(t, s.Builder, buildOrder(testCert))),
				)
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				if returnedCert.Status.LastFailureTime != nil {
					t.Errorf("Expected status.lastFailureTime to be nil, but it is: %v", returnedCert.Status.LastFailureTime)
				}
			},
			Err: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
			}
			if test.StringGenerator == nil {
				test.StringGenerator = stringGenerator
			}
			test.Setup(t)
			certCopy := test.Certificate.DeepCopy()
			err := test.Acme.Prepare(test.Ctx, certCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, certCopy, err)
		})
	}
}
