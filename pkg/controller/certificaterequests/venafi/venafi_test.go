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
	"github.com/jetstack/cert-manager/pkg/issuer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testcr "github.com/jetstack/cert-manager/pkg/controller/certificaterequests/test"
	controllertest "github.com/jetstack/cert-manager/pkg/controller/test"
	internalvenafi "github.com/jetstack/cert-manager/pkg/internal/venafi"
	internalvenafifake "github.com/jetstack/cert-manager/pkg/internal/venafi/fake"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
	testlisters "github.com/jetstack/cert-manager/test/unit/listers"
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

func checkOnlyCertReturned(builder *controllertest.Builder, args ...interface{}) {
	resp, ok := args[0].(*issuer.IssueResponse)
	if !ok {
		builder.T.Errorf("unexpected argument to be of type IssuerResponse: %+v", args[0])
	}

	if string(resp.Certificate) != "returned cert" {
		builder.T.Errorf("unexpected returned cert, exp=returned cert got=%s",
			resp.Certificate)
	}

	if len(resp.PrivateKey) > 0 || len(resp.CA) > 0 {
		builder.T.Errorf("expected both private key and CA to be empty, got=%s %s",
			resp.PrivateKey, resp.CA)
	}
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
			return []byte("returned cert"), nil
		},
	}

	tests := map[string]testT{
		"tpp: if fail to build client based on missing secret then return nil and hard fail": {
			certificateRequest: tppCR,
			issuer:             tppIssuer,
			builder: &controllertest.Builder{
				ExpectedEvents: []string{
					`Normal MissingSecret Required secret resource not found: secret "test-tpp-secret" not found`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},
		"tpp: if fail to build client based on secret lister transient error then return err and set pending": {
			certificateRequest: tppCR,
			issuer:             tppIssuer,
			builder: &controllertest.Builder{
				ExpectedEvents: []string{
					`Normal ErrorVenafiInit Failed to initialise venafi client for signing: this is a network error`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeSecretLister: failGetSecretLister,
			expectedErr:      true,
		},
		"cloud: if fail to build client based on missing secret then return nil and hard fail": {
			certificateRequest: cloudCR,
			issuer:             cloudIssuer,
			builder: &controllertest.Builder{
				ExpectedEvents: []string{
					`Normal MissingSecret Required secret resource not found: secret "test-cloud-secret" not found`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},
		"cloud: if fail to build client based on secret lister transient error then return err and set pending": {
			certificateRequest: cloudCR,
			issuer:             cloudIssuer,
			builder: &controllertest.Builder{
				ExpectedEvents: []string{
					`Normal ErrorVenafiInit Failed to initialise venafi client for signing: this is a network error`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeSecretLister: failGetSecretLister,
			expectedErr:      true,
		},
		"tpp: if sign returns pending error then set pending and return err": {
			certificateRequest: tppCR,
			issuer:             tppIssuer,
			builder: &controllertest.Builder{
				KubeObjects: []runtime.Object{tppSecret},
				ExpectedEvents: []string{
					"Normal IssuancePending venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsPending,
			expectedErr:      true,
		},
		"cloud: if sign returns pending error then set pending and return err": {
			certificateRequest: cloudCR,
			issuer:             cloudIssuer,
			builder: &controllertest.Builder{
				KubeObjects: []runtime.Object{cloudSecret},
				ExpectedEvents: []string{
					"Normal IssuancePending venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsPending,
			expectedErr:      true,
		},
		"tpp: if sign returns timeout error then set failed and return nil": {
			certificateRequest: tppCR,
			issuer:             tppIssuer,
			builder: &controllertest.Builder{
				KubeObjects: []runtime.Object{tppSecret},
				ExpectedEvents: []string{
					"Warning Timeout timed out waiting for venafi certificate, the request will be retried: Operation timed out. You may try retrieving the certificate later using Pickup ID: test-cert-id",
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsTimeout,
			expectedErr:      false,
		},
		"cloud: if sign returns timeout error then set failed and return nil": {
			certificateRequest: cloudCR,
			issuer:             cloudIssuer,
			builder: &controllertest.Builder{
				KubeObjects: []runtime.Object{cloudSecret},
				ExpectedEvents: []string{
					"Warning Timeout timed out waiting for venafi certificate, the request will be retried: Operation timed out. You may try retrieving the certificate later using Pickup ID: test-cert-id",
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsTimeout,
			expectedErr:      false,
		},
		"tpp: if sign returns generic error then set pending and return error": {
			certificateRequest: tppCR,
			issuer:             tppIssuer,
			builder: &controllertest.Builder{
				KubeObjects: []runtime.Object{tppSecret},
				ExpectedEvents: []string{
					"Normal Retrieve failed to obtain venafi certificate: this is an error",
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsGenericError,
			expectedErr:      true,
		},
		"cloud: if sign returns generic error then set pending and return error": {
			certificateRequest: cloudCR,
			issuer:             cloudIssuer,
			builder: &controllertest.Builder{
				KubeObjects: []runtime.Object{cloudSecret},
				ExpectedEvents: []string{
					"Normal Retrieve failed to obtain venafi certificate: this is an error",
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsGenericError,
			expectedErr:      true,
		},
		"tpp: if sign returns cert then return cert and not failed": {
			certificateRequest: tppCR,
			issuer:             tppIssuer,
			builder: &controllertest.Builder{
				KubeObjects:    []runtime.Object{tppSecret},
				ExpectedEvents: []string{},
				CheckFn:        checkOnlyCertReturned,
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsCert,
			expectedErr:      false,
		},
		"cloud: if sign returns cert then return cert and not failed": {
			certificateRequest: cloudCR,
			issuer:             cloudIssuer,
			builder: &controllertest.Builder{
				KubeObjects:    []runtime.Object{cloudSecret},
				ExpectedEvents: []string{},
				CheckFn:        checkOnlyCertReturned,
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsCert,
			expectedErr:      false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
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
	test.builder.Start()
	defer test.builder.Stop()

	c := NewVenafi(test.builder.Context)

	if test.fakeSecretLister != nil {
		c.secretsLister = test.fakeSecretLister
	}

	if test.fakeClient != nil {
		c.clientBuilder = func(namespace string, secretsLister corelisters.SecretLister,
			issuer cmapi.GenericIssuer) (internalvenafi.Interface, error) {
			return test.fakeClient, nil
		}
	}

	test.builder.Sync()

	resp, err := c.Sign(context.Background(), test.certificateRequest, test.issuer)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}
	test.builder.CheckAndFinish(resp, err)
}
