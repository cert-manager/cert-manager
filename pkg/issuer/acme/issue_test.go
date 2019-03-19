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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/kr/pretty"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func generatePrivateKey(t *testing.T) *rsa.PrivateKey {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	return pk
}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func generateSelfSignedCert(t *testing.T, crt *v1alpha1.Certificate, key crypto.Signer, notBefore time.Time, duration time.Duration) (derBytes, pemBytes []byte) {
	commonName := pki.CommonNameForCertificate(crt)
	dnsNames := pki.DNSNamesForCertificate(crt)
	ipAddresses := pki.IPAddressesForCertificate(crt)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Errorf("failed to generate serial number: %v", err)
		t.FailNow()
	}

	template := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(duration),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Errorf("error signing cert: %v", err)
		t.FailNow()
	}

	pemByteBuffer := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemByteBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		t.Errorf("failed to encode cert: %v", err)
		t.FailNow()
	}

	return derBytes, pemByteBuffer.Bytes()
}

// This set of tests is an ordered representation of the happy path of Issue
// being called.
func TestIssueHappyPath(t *testing.T) {
	// Build required test PKI fixtures
	pk := generatePrivateKey(t)
	pkBytes := pki.EncodePKCS1PrivateKey(pk)
	testCertPrivateKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testcrt-tls",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"tls.key": pkBytes,
		},
	}
	testCertCSRTemplate := &x509.CertificateRequest{
		Version: 3,
		// SignatureAlgorithm: sigAlgo,
		Subject: pkix.Name{
			CommonName: "test.com",
		},
	}
	testCertCSR, err := pki.EncodeCSR(testCertCSRTemplate, pk)
	if err != nil {
		t.Errorf("error generating csr1: %v", err)
	}

	// build actual test fixtures
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
	}

	_, testCertSignedBytesPEM := generateSelfSignedCert(t, testCert, pk, time.Now(), time.Hour*24*365)
	_, testCertExpiringSignedBytesPEM := generateSelfSignedCert(t, testCert, pk, time.Now().Add(-4*time.Minute), time.Minute*5)
	testCertEmptyOrder, _ := buildOrder(testCert, testCertCSR)
	testCertPendingOrder := testCertEmptyOrder.DeepCopy()
	testCertPendingOrder.Status.State = v1alpha1.Pending
	testCertValidOrder := testCertEmptyOrder.DeepCopy()
	testCertValidOrder.Status.State = v1alpha1.Valid
	testCertValidOrder.Status.Certificate = testCertSignedBytesPEM
	testCertExpiredCertOrder := testCertValidOrder.DeepCopy()
	testCertExpiredCertOrder.Status.Certificate = testCertExpiringSignedBytesPEM

	tests := map[string]acmeFixture{
		"generate a new private key if one does not exist": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{},
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				// returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp.PrivateKey == nil {
					t.Errorf("expected new private key to be generated")
				}
			},
			Err: false,
		},
		"create a new order if a private key exists and there isn't an existing order": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{},
				KubeObjects:        []runtime.Object{testCertPrivateKeySecret},
				ExpectedActions: []testpkg.Action{
					testpkg.NewCustomMatch(coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testCertEmptyOrder.Namespace, testCertEmptyOrder),
						func(exp, actual coretesting.Action) error {
							expOrder := exp.(coretesting.CreateAction).GetObject().(*v1alpha1.Order)
							actOrder := actual.(coretesting.CreateAction).GetObject().(*v1alpha1.Order)
							expOrderCopy := expOrder.DeepCopy()
							expOrderCopy.Spec.CSR = actOrder.Spec.CSR
							if !reflect.DeepEqual(expOrderCopy, actOrder) {
								return fmt.Errorf("unexpected difference: %s", pretty.Diff(expOrderCopy, actOrder))
							}
							return nil
						}),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp != nil {
					t.Errorf("expected IssuerResponse to be nil")
				}
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("output was not as expected: %s", pretty.Diff(returnedCert, testCert))
				}
			},
		},
		"do nothing if the existing order is pending and up-to-date": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testCertPendingOrder},
				KubeObjects:        []runtime.Object{testCertPrivateKeySecret},
				ExpectedActions:    []testpkg.Action{},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp != nil {
					t.Errorf("expected IssuerResponse to be nil")
				}
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("output was not as expected: %s", pretty.Diff(returnedCert, testCert))
				}
			},
			Err: false,
		},
		"retrieve the Certificate bytes from the Order if it is 'valid'": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testCertValidOrder},
				KubeObjects:        []runtime.Object{testCertPrivateKeySecret},
				ExpectedActions:    []testpkg.Action{},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("output was not as expected: %s", pretty.Diff(returnedCert, testCert))
				}
				if !reflect.DeepEqual(resp.Certificate, testCertSignedBytesPEM) {
					t.Errorf("unexpected certificate returned: %s", pretty.Diff(string(resp.Certificate), string(testCertSignedBytesPEM)))
				}
				if !reflect.DeepEqual(resp.PrivateKey, pkBytes) {
					t.Errorf("unexpected private key returned: %v", resp.PrivateKey)
				}
			},
			Err: false,
		},
		"trigger a renewal if the certificate associated with the order is nearing expiry": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				Context: &controller.Context{
					IssuerOptions: controller.IssuerOptions{
						RenewBeforeExpiryDuration: time.Hour * 2,
					},
				},
				CertManagerObjects: []runtime.Object{testCertExpiredCertOrder},
				KubeObjects:        []runtime.Object{testCertPrivateKeySecret},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewDeleteAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testCertValidOrder.Namespace, testCertValidOrder.Name),
					),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp != nil {
					t.Errorf("expected IssuerResponse to be nil, but was: %v", resp)
				}
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("output was not as expected: %s", pretty.Diff(returnedCert, testCert))
				}
			},
			Err: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
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
			test.Finish(t, certCopy, resp, err)
		})
	}
}

func TestIssueRetryCases(t *testing.T) {
	nowTime := time.Now()
	nowMetaTime := metav1.NewTime(nowTime)
	fixedClock := fakeclock.NewFakeClock(nowTime)

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
	}
	invalidTestCert := testCert.DeepCopy()
	invalidTestCert.Spec.CommonName = "test2.com"

	testOrder, _ := buildOrder(testCert, nil)

	recentlyFailedCertificate := testCert.DeepCopy()
	recentlyFailedCertificate.Status.LastFailureTime = &nowMetaTime

	notRecentlyFailedCertificate := testCert.DeepCopy()
	pastTime := metav1.NewTime(time.Now().Add(time.Hour * -24))
	notRecentlyFailedCertificate.Status.LastFailureTime = &pastTime

	testOrderCSR1Set := testOrder.DeepCopy()
	testOrderCSR1Set.Spec.CSR = testCSR1
	pendingTestOrderCSR1 := testOrderCSR1Set.DeepCopy()
	pendingTestOrderCSR1.Status.State = v1alpha1.Pending
	failedTestOrderCSR1 := testOrderCSR1Set.DeepCopy()
	failedTestOrderCSR1.Status.State = v1alpha1.Invalid

	testOrderCSR2Set := testOrder.DeepCopy()
	testOrderCSR2Set.Spec.CSR = testCSR2

	readyTestOrder := testOrder.DeepCopy()
	readyTestOrder.Status.State = v1alpha1.Ready
	invalidTestOrder, _ := buildOrder(invalidTestCert, nil)

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
		"delete existing order and create a new one immediately if the order hash has changed": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{invalidTestOrder},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewDeleteAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), invalidTestOrder.Namespace, invalidTestOrder.Name),
					),
					testpkg.NewCustomMatch(coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrder.Namespace, testOrder),
						func(exp, actual coretesting.Action) error {
							expOrder := exp.(coretesting.CreateAction).GetObject().(*v1alpha1.Order)
							actOrder := actual.(coretesting.CreateAction).GetObject().(*v1alpha1.Order)
							expOrderCopy := expOrder.DeepCopy()
							expOrderCopy.Spec.CSR = actOrder.Spec.CSR
							if !reflect.DeepEqual(expOrderCopy, actOrder) {
								return fmt.Errorf("unexpected difference: %s", pretty.Diff(expOrderCopy, actOrder))
							}
							return nil
						}),
				},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp != nil {
					t.Errorf("expected IssuerResponse to be nil")
				}
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, testCert))
				}
			},
			Err: false,
		},

		"delete existing order if the csr is signed by a different private key": {
			Certificate: testCert,
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
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp != nil {
					t.Errorf("expected IssuerResponse to be nil")
				}
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, testCert))
				}
			},
			Err: false,
		},

		"delete existing order if the csr field is not set": {
			Certificate: testCert,
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
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp != nil {
					t.Errorf("expected IssuerResponse to be nil")
				}
				if !reflect.DeepEqual(returnedCert, testCert) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, testCert))
				}
			},
			Err: false,
		},

		"delete existing order if the back-off time has passed": {
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
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp != nil {
					t.Errorf("expected IssuerResponse to be nil")
				}
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
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp != nil {
					t.Errorf("expected IssuerResponse to be nil")
				}
				// the resource should not be changed
				if !reflect.DeepEqual(returnedCert, recentlyFailedCertificate) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, recentlyFailedCertificate))
				}
			},
			Err: true,
		},

		"set the last failure time if the order has failed and there is not a failure time set": {
			Certificate: testCert,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{failedTestOrderCSR1},
				KubeObjects:        []runtime.Object{testCertExistingPKSecret},
				ExpectedActions:    []testpkg.Action{},
			},
			PreFn: func(t *testing.T, s *acmeFixture) {
			},
			CheckFn: func(t *testing.T, s *acmeFixture, args ...interface{}) {
				returnedCert := args[0].(*v1alpha1.Certificate)
				resp := args[1].(*issuer.IssueResponse)
				// err := args[2].(error)

				if resp != nil {
					t.Errorf("expected IssuerResponse to be nil")
				}
				// the resource should have the last failure time set
				if !reflect.DeepEqual(returnedCert, recentlyFailedCertificate) {
					t.Errorf("expected certificate order ref to be nil: %s", pretty.Diff(returnedCert, recentlyFailedCertificate))
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
			if test.Clock == nil {
				test.Clock = fixedClock
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
			test.Finish(t, certCopy, resp, err)
		})
	}
}
