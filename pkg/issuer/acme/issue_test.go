package acme

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"
	"time"

	"github.com/kr/pretty"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func TestIssue(t *testing.T) {
	const generateNameSuffix = "test"
	stringGenerator := testpkg.FixedString(generateNameSuffix)

	pk1, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	pk2, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	testCertCSRTemplate := &x509.CertificateRequest{
		Version: 3,
		// SignatureAlgorithm: sigAlgo,
		Subject: pkix.Name{
			CommonName: "test.com",
		},
	}
	testCSR1, err := pki.EncodeCSR(testCertCSRTemplate, pk1)
	if err != nil {
		t.Errorf("error generating csr1: %v", err)
	}
	testCSR2, err := pki.EncodeCSR(testCertCSRTemplate, pk2)
	if err != nil {
		t.Errorf("error generating csr2: %v", err)
	}

	testCert := &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "testcrt", Namespace: "default"},
		Spec: v1alpha1.CertificateSpec{
			SecretName: "testcrt-tls",
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
		Status: v1alpha1.CertificateStatus{
			ACME: &v1alpha1.CertificateACMEStatus{},
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

	testOrder := buildOrder(testCert, nil)
	testOrder.Name = testCertOrderRefSet.Status.ACMEStatus().OrderRef.Name

	testOrderCSR1Set := testOrder.DeepCopy()
	testOrderCSR1Set.Spec.CSR = testCSR1
	pendingTestOrderCSR1 := testOrderCSR1Set.DeepCopy()
	pendingTestOrderCSR1.Status.State = v1alpha1.Pending
	failedTestOrderCSR1 := testOrderCSR1Set.DeepCopy()
	failedTestOrderCSR1.Status.State = v1alpha1.Failed

	testOrderCSR2Set := testOrder.DeepCopy()
	testOrderCSR2Set.Spec.CSR = testCSR2

	readyTestOrder := testOrder.DeepCopy()
	readyTestOrder.Status.State = v1alpha1.Ready
	invalidTestOrder := buildOrder(invalidTestCert, nil)
	invalidTestOrder.Name = testCertOrderRefSet.Status.ACMEStatus().OrderRef.Name

	pkBytes := pki.EncodePKCS1PrivateKey(pk1)
	testCertExistingPKSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testcrt-tls",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"tls.key": pkBytes,
		},
	}

	tests := map[string]acmeFixture{
		"should generate a new private key and requeue certificate if one does not exist": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{},
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				// returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey == nil {
					t.Errorf("expected new private key to be generated")
				}
				if resp.Requeue != true {
					t.Errorf("expected certificate to be requeued")
				}
			},
			Err: false,
		},
		"should create a new order and set order status if a private key exists": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions: []testpkg.Action{
					testpkg.NewCustomMatch(coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, testOrder),
						func(exp, actual coretesting.Action) bool {
							expOrder := exp.(coretesting.CreateAction).GetObject().(*v1alpha1.Order)
							actOrder := actual.(coretesting.CreateAction).GetObject().(*v1alpha1.Order)
							expOrderCopy := expOrder.DeepCopy()
							expOrderCopy.Spec.CSR = actOrder.Spec.CSR
							return reflect.DeepEqual(expOrderCopy, actOrder)
						}),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey != nil {
					t.Errorf("unexpected PrivateKey response set")
				}
				if resp.Requeue == true {
					t.Errorf("expected certificate to not be requeued")
				}
				if !reflect.DeepEqual(returnedCert, testCertOrderRefSet) {
					t.Errorf("output was not as expected: %s", pretty.Diff(returnedCert, testCertOrderRefSet))
				}
			},
			Err: false,
		},
		"should create new order if the existing order referenced does not exist": {
			Certificate: testCertOrderRefSet,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions: []testpkg.Action{
					testpkg.NewCustomMatch(coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, testOrder),
						func(exp, actual coretesting.Action) bool {
							expOrder := exp.(coretesting.CreateAction).GetObject().(*v1alpha1.Order)
							actOrder := actual.(coretesting.CreateAction).GetObject().(*v1alpha1.Order)
							expOrderCopy := expOrder.DeepCopy()
							expOrderCopy.Spec.CSR = actOrder.Spec.CSR
							return reflect.DeepEqual(expOrderCopy, actOrder)
						}),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey != nil {
					t.Errorf("unexpected PrivateKey response set")
				}
				if resp.Requeue == true {
					t.Errorf("expected certificate to not be requeued")
				}
				if !reflect.DeepEqual(returnedCert, testCertOrderRefSet) {
					t.Errorf("output was not as expected: %s", pretty.Diff(returnedCert, testCertOrderRefSet))
				}
			},
			Err: false,
		},
		"should perform no action and not requeue if the order does not have a state set": {
			Certificate: testCertOrderRefSet,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{pendingTestOrderCSR1},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions:    []testpkg.Action{},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey != nil {
					t.Errorf("unexpected PrivateKey response set")
				}
				if resp.Certificate != nil {
					t.Errorf("unexpected Certificate response set")
				}
				if resp.Requeue == true {
					t.Errorf("expected certificate to not be requeued")
				}
				// there should be no update
				if !reflect.DeepEqual(returnedCert, testCertOrderRefSet) {
					t.Errorf("output was not as expected: %s", pretty.Diff(returnedCert, testCertOrderRefSet))
				}
			},
			Err: false,
		},
		"delete existing order and set orderRef to nil if the order hash has changed": {
			Certificate: testCertOrderRefSet,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{invalidTestOrder},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewDeleteAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), invalidTestOrder.Namespace, invalidTestOrder.Name),
					),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey != nil {
					t.Errorf("unexpected PrivateKey response set")
				}
				if resp.Certificate != nil {
					t.Errorf("unexpected Certificate response set")
				}
				if resp.Requeue == true {
					t.Errorf("expected certificate to not be requeued")
				}
				// the orderRef field should be set to nil
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, testCert))
				}
			},
			Err: false,
		},

		"delete existing order and set orderRef to nil if the csr is signed by a different private key": {
			Certificate: testCertOrderRefSet,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrderCSR2Set},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewDeleteAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, testOrder.Name),
					),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey != nil {
					t.Errorf("unexpected PrivateKey response set")
				}
				if resp.Certificate != nil {
					t.Errorf("unexpected Certificate response set")
				}
				if resp.Requeue == true {
					t.Errorf("expected certificate to not be requeued")
				}
				// the orderRef field should be set to nil
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, testCert))
				}
			},
			Err: false,
		},

		"delete existing order and set orderRef to nil if the csr field is not set": {
			Certificate: testCertOrderRefSet,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrder},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewDeleteAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, testOrder.Name),
					),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey != nil {
					t.Errorf("unexpected PrivateKey response set")
				}
				if resp.Certificate != nil {
					t.Errorf("unexpected Certificate response set")
				}
				if resp.Requeue == true {
					t.Errorf("expected certificate to not be requeued")
				}
				// the orderRef field should be set to nil
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, testCert))
				}
			},
			Err: false,
		},

		"should return an error if the certificate resource is in 'back-off' due to a failed order": {
			Certificate: recentlyFailedCertificate,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{failedTestOrderCSR1},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions:    []testpkg.Action{},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey != nil {
					t.Errorf("unexpected PrivateKey response set")
				}
				if resp.Certificate != nil {
					t.Errorf("unexpected Certificate response set")
				}
				if resp.Requeue == true {
					t.Errorf("expected certificate to not be immediately requeued")
				}
				// the resource should not be changed
				if !reflect.DeepEqual(returnedCert, recentlyFailedCertificate) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, recentlyFailedCertificate))
				}
			},
			Err: true,
		},

		"delete existing order and set orderRef to nil if the back-off time has passed": {
			Certificate: notRecentlyFailedCertificate,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{failedTestOrderCSR1},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewDeleteAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), failedTestOrderCSR1.Namespace, failedTestOrderCSR1.Name),
					),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey != nil {
					t.Errorf("unexpected PrivateKey response set")
				}
				if resp.Certificate != nil {
					t.Errorf("unexpected Certificate response set")
				}
				if resp.Requeue == true {
					t.Errorf("expected certificate to not be requeued")
				}
				// the orderRef field should be set to nil
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, testCert))
				}
			},
			Err: false,
		},

		// // Success cases
		// "should not return an error if the existing order is in a 'ready' state": {
		// 	Certificate: testCertOrderRefSet,
		// 	Builder: &testpkg.Builder{
		// 		CertManagerObjects: []runtime.Object{readyTestOrder},
		// 	},
		// 	PreFn: func(t *testing.T, s *acmeFixture) {
		// 	},
		// 	CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
		// 		returnedCert := args[0].(*v1alpha1.Certificate)
		// 		if !reflect.DeepEqual(returnedCert, s.Certificate) {
		// 			t.Errorf("expected %+v to equal %+v", returnedCert, s.Certificate)
		// 		}
		// 	},
		// 	Err: false,
		// },
		// "should create an order and update the Certificate status if no existing order is named in status": {
		// 	Certificate: testCert,
		// 	Builder: &testpkg.Builder{
		// 		ExpectedActions: []coretesting.Action{
		// 			coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, testOrder),
		// 		},
		// 	},
		// 	PreFn: func(t *testing.T, s *acmeFixture) {
		// 	},
		// 	CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
		// 		returnedCert := args[0].(*v1alpha1.Certificate)
		// 		if returnedCert.Status.ACMEStatus().OrderRef.Name != testOrder.Name {
		// 			t.Errorf("Expected orderRef.name to equal %q, but it is %q", testOrder.Name, returnedCert.Status.ACMEStatus().OrderRef.Name)
		// 		}
		// 	},
		// 	Err: true,
		// },
		// "should create a new order and update Certificate status if the one referenced no longer exists": {
		// 	Certificate: testCertOrderRefSet,
		// 	Builder: &testpkg.Builder{
		// 		ExpectedActions: []coretesting.Action{
		// 			coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, testOrder),
		// 		},
		// 	},
		// 	CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
		// 		returnedCert := args[0].(*v1alpha1.Certificate)
		// 		if returnedCert.Status.ACMEStatus().OrderRef.Name != testOrder.Name {
		// 			t.Errorf("Expected orderRef.name to equal %q, but it is %q", testOrder.Name, returnedCert.Status.ACMEStatus().OrderRef.Name)
		// 		}
		// 	},
		// 	Err: true,
		// },
		// "should delete the existing order, create a new one and update status if the order hash has changed": {
		// 	Certificate: testCertOrderRefSet,
		// 	Builder: &testpkg.Builder{
		// 		CertManagerObjects: []runtime.Object{invalidTestOrder},
		// 		// create an Order based on a different version of the test cert
		// 		ExpectedActions: []coretesting.Action{
		// 			coretesting.NewDeleteAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), invalidTestOrder.Namespace, invalidTestOrder.Name),
		// 			coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, buildOrder(testCert, nil)),
		// 		},
		// 	},
		// 	PreFn: func(t *testing.T, s *acmeFixture) {
		// 		s.FakeCMClient().PrependReactor("delete", "orders",
		// 			s.EnsureReactorCalled("existing order deleted",
		// 				testpkg.ObjectDeletedReactor(t, s.Builder, invalidTestOrder)),
		// 		)
		// 		s.FakeCMClient().PrependReactor("create", "orders",
		// 			s.EnsureReactorCalled("new order created",
		// 				testpkg.ObjectCreatedReactor(t, s.Builder, buildOrder(testCert, nil))),
		// 		)
		// 	},
		// 	CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
		// 	},
		// 	Err: true,
		// },
		// // Failure cases
		// "should set failure time and error if the referenced order has failed and last failure is not set": {
		// 	Certificate: testCertOrderRefSet,
		// 	Builder: &testpkg.Builder{
		// 		CertManagerObjects: []runtime.Object{failedTestOrder},
		// 		// create an Order based on a different version of the test cert
		// 		ExpectedActions: []coretesting.Action{},
		// 	},
		// 	PreFn: func(t *testing.T, s *acmeFixture) {
		// 		s.Builder.Sync()
		// 	},
		// 	CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
		// 		returnedCert := args[0].(*v1alpha1.Certificate)
		// 		if returnedCert.Status.LastFailureTime == nil {
		// 			t.Errorf("expected lastFailureTime to be set")
		// 		}
		// 	},
		// 	Err: true,
		// },
		// "should not set failure time, but return error if the referenced order has failed and last failure < failureBackoffPeriod ago": {
		// 	Certificate: recentlyFailedCertificate,
		// 	Builder: &testpkg.Builder{
		// 		CertManagerObjects: []runtime.Object{failedTestOrder},
		// 		// create an Order based on a different version of the test cert
		// 		ExpectedActions: []coretesting.Action{},
		// 	},
		// 	PreFn: func(t *testing.T, s *acmeFixture) {
		// 		s.Builder.Sync()
		// 	},
		// 	CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
		// 		returnedCert := args[0].(*v1alpha1.Certificate)
		// 		if !returnedCert.Status.LastFailureTime.Equal(recentlyFailedCertificate.Status.LastFailureTime) {
		// 			t.Errorf("Expected status.lastFailureTime to equal %q, but it is %q", recentlyFailedCertificate.Status.LastFailureTime, returnedCert.Status.LastFailureTime)
		// 		}
		// 	},
		// 	Err: true,
		// },
		// "should clear failure time and create a new order if the lastFailureTime > failureBackoffPeriod minutes ago": {
		// 	Certificate: notRecentlyFailedCertificate,
		// 	Builder: &testpkg.Builder{
		// 		CertManagerObjects: []runtime.Object{failedTestOrder},
		// 		// create an Order based on a different version of the test cert
		// 		ExpectedActions: []coretesting.Action{
		// 			coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, buildOrder(testCert, nil)),
		// 		},
		// 	},
		// 	PreFn: func(t *testing.T, s *acmeFixture) {
		// 		s.FakeCMClient().PrependReactor("create", "orders",
		// 			s.EnsureReactorCalled("new order created",
		// 				testpkg.ObjectCreatedReactor(t, s.Builder, buildOrder(testCert, nil))),
		// 		)
		// 	},
		// 	CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
		// 		returnedCert := args[0].(*v1alpha1.Certificate)
		// 		if returnedCert.Status.LastFailureTime != nil {
		// 			t.Errorf("Expected status.lastFailureTime to be nil, but it is: %v", returnedCert.Status.LastFailureTime)
		// 		}
		// 	},
		// 	Err: true,
		// },
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
			resp, err := test.Acme.Issue(test.Ctx, certCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			if resp.Requeue == true {
				if !reflect.DeepEqual(test.Certificate, certCopy) {
					t.Errorf("Requeue should never be true if the Certificate is modified to prevent race conditions")
				}

				if err != nil {
					t.Errorf("Requeue cannot be true if err is true")
				}
			}
			test.Finish(t, certCopy, resp, err)
		})
	}
}
