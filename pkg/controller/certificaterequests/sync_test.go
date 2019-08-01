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

package certificaterequests

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	clock "k8s.io/utils/clock/testing"

	"github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests/fake"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	_ "github.com/jetstack/cert-manager/pkg/issuer/selfsigned"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func generateCSR(commonName string) ([]byte, error) {
	csr := &x509.CertificateRequest{
		Version:            3,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		Subject: pkix.Name{
			Organization: []string{"my-org"},
			CommonName:   commonName,
		},
		URIs: []*url.URL{
			{
				Scheme: "http",
				Host:   "example.com",
			},
		},
		IPAddresses: []net.IP{
			net.IPv4(8, 8, 8, 8),
		},
	}

	sk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		return nil, err
	}

	csrBytes, err := pki.EncodeCSR(csr, sk)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})

	return csrPEM, nil
}

func generatePrivateKey(t *testing.T) *rsa.PrivateKey {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	return pk
}

func generateSelfSignedCert(t *testing.T, cr *cmapi.CertificateRequest, sn *big.Int, key crypto.Signer, notBefore, notAfter time.Time) []byte {
	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		t.Errorf("failed to generate cert template from CSR: %v", err)
		t.FailNow()
	}

	template.NotAfter = notAfter
	template.NotBefore = notBefore

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
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

	return pemByteBuffer.Bytes()
}

func TestSync(t *testing.T) {
	nowTime := time.Now()
	nowMetaTime := metav1.NewTime(nowTime)
	fixedClock := clock.NewFakeClock(nowTime)

	csr, err := generateCSR("csr")
	if err != nil {
		t.Errorf("failed to generate CSR for testing: %s", err)
		t.FailNow()
	}

	pk := generatePrivateKey(t)

	exampleCR := gen.CertificateRequest("test",
		gen.SetCertificateRequestIsCA(false),
		gen.SetCertificateRequestIssuer(cmapi.ObjectReference{Name: "test"}),
		gen.SetCertificateRequestCSR(csr),
		gen.SetCertificateRequestIssuer(cmapi.ObjectReference{
			Kind: "Issuer",
			Name: "fake-issuer",
		}),
	)

	exampleCRIssuePendingCondition := gen.CertificateRequestFrom(exampleCR,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionReady,
			Status:             cmapi.ConditionFalse,
			Reason:             "Pending",
			Message:            "Certificate issuance pending",
			LastTransitionTime: &nowMetaTime,
		}),
	)

	exampleCRIssuerNotFoundPendingCondition := gen.CertificateRequestFrom(exampleCR,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionReady,
			Status:             cmapi.ConditionFalse,
			Reason:             "Pending",
			Message:            "Referenced Issuer not found",
			LastTransitionTime: &nowMetaTime,
		}),
	)

	exampleFailedCR := gen.CertificateRequestFrom(exampleCR,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionReady,
			Status:             cmapi.ConditionFalse,
			Reason:             cmapi.CertificateRequestReasonFailed,
			LastTransitionTime: &nowMetaTime,
		}),
	)

	certPEM := generateSelfSignedCert(t, exampleCR, nil, pk, nowTime, nowTime.Add(time.Hour*12))
	certPEMExpired := generateSelfSignedCert(t, exampleCR, nil, pk, nowTime.Add(-time.Hour*13), nowTime.Add(-time.Hour*12))

	exampleSignedCR := exampleCR.DeepCopy()
	exampleSignedCR.Status.Certificate = certPEM

	exampleSignedExpiredCR := exampleCR.DeepCopy()
	exampleSignedExpiredCR.Status.Certificate = certPEMExpired

	exampleCRReadyCondition := gen.CertificateRequestFrom(exampleSignedCR,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionReady,
			Status:             cmapi.ConditionTrue,
			Reason:             "Ready",
			Message:            "Certificate has been issued successfully",
			LastTransitionTime: &nowMetaTime,
		}),
	)

	exampleCRExpiredReadyCondition := exampleSignedExpiredCR
	exampleCRExpiredReadyCondition.Status.Conditions = exampleCRReadyCondition.Status.Conditions

	exampleGarbageCertCR := exampleSignedCR.DeepCopy()
	exampleGarbageCertCR.Status.Certificate = []byte("not a certificate")
	exampleCRGarbageCondition := gen.CertificateRequestFrom(exampleGarbageCertCR,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionReady,
			Status:             cmapi.ConditionFalse,
			Reason:             "Failed",
			Message:            "Failed to decode certificate PEM",
			LastTransitionTime: &nowMetaTime,
		}),
	)

	exampleEmptyCSRCR := exampleCR.DeepCopy()
	exampleEmptyCSRCR.Spec.CSRPEM = make([]byte, 0)

	exampleFailedValidationCR := gen.CertificateRequestFrom(exampleEmptyCSRCR,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionReady,
			Status:             cmapi.ConditionFalse,
			Reason:             "Failed",
			Message:            "Validation failed: spec.csr: Required value: must be specified",
			LastTransitionTime: &nowMetaTime,
		}),
	)

	exampleCRWrongIssuerRefGroup := exampleCR.DeepCopy()
	exampleCRWrongIssuerRefGroup.Spec.IssuerRef.Group = "notcertmanager.k8s.io"

	exampleCRWrongIssuerRefType := exampleCR.DeepCopy()
	exampleCRWrongIssuerRefType.Spec.IssuerRef.Name = "selfsigned-issuer"

	exampleCRCorrectIssuerRefGroup := exampleCRWrongIssuerRefGroup.DeepCopy()
	exampleCRCorrectIssuerRefGroup.Spec.IssuerRef.Group = "certmanager.k8s.io"
	exampleCRReadyConditionWithGroupRef := exampleCRReadyCondition.DeepCopy()
	exampleCRReadyConditionWithGroupRef.Spec.IssuerRef.Group = "certmanager.k8s.io"

	tests := map[string]testT{
		"should update certificate request with CertPending if issuer does not return a response": {
			certificateRequest: gen.CertificateRequest("test",
				gen.SetCertificateRequestIsCA(false),
				gen.SetCertificateRequestCSR(csr),
				gen.SetCertificateRequestIssuer(cmapi.ObjectReference{
					Kind: "Issuer",
					Name: "fake-issuer",
				}),
			),
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					// By not returning a response, we trigger a 'no-op' action which
					// causes the certificate request controller to update the status of
					// the CertificateRequest with !Ready - CertPending.
					return nil, nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Issuer("fake-issuer",
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
					gen.CertificateRequest("test"),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleCRIssuePendingCondition,
					)),
				},
			},
		},
		"should update the status with a freshly signed certificate only when one doesn't exist and group ref=''": {
			certificateRequest: exampleCR,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						Certificate: certPEM,
					}, nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test"),
					gen.Issuer("fake-issuer",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmapi.ConditionTrue,
						}),
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
					)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleCRReadyCondition,
					)),
				},
				ExpectedEvents: []string{"Normal Issued Certificate fetched from issuer successfully"},
			},
		},
		"should update the status with a freshly signed certificate only when one doesn't exist and issuer group ref='certmanager.k8s.io'": {
			certificateRequest: exampleCRCorrectIssuerRefGroup,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						Certificate: certPEM,
					}, nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test"),
					gen.Issuer("fake-issuer",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmapi.ConditionTrue,
						}),
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleCRReadyConditionWithGroupRef,
					)),
				},
				ExpectedEvents: []string{"Normal Issued Certificate fetched from issuer successfully"},
			},
		},
		"should exit sync nil if issuerRef group does not match certmanager.k8s.io": {
			certificateRequest: exampleCRWrongIssuerRefGroup,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, errors.New("unexpected sign call")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test"),
					gen.Issuer("fake-issuer",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmapi.ConditionTrue,
						}),
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
					),
				},
				ExpectedActions: []testpkg.Action{}, // no update
			},
		},
		"should not update certificate request if certificate exists, even if out of date": {
			certificateRequest: exampleSignedExpiredCR,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, errors.New("unexpected sign call")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test"),
					gen.Issuer("fake-issuer",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmapi.ConditionTrue,
						}),
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
					),
				},
				ExpectedActions: []testpkg.Action{}, // no update
			},
		},
		"fail if bytes contains no certificate but len > 0": {
			certificateRequest: exampleGarbageCertCR,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, errors.New("unexpected sign call")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test"),
					gen.Issuer("fake-issuer",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmapi.ConditionTrue,
						}),
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleCRGarbageCondition,
					)),
				},
			},
		},
		"return nil if generic issuer doesn't exist, will sync when on ready": {
			certificateRequest: exampleCR,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, errors.New("unexpected sign call")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleCRIssuerNotFoundPendingCondition,
					)),
				},
				ExpectedEvents: []string{"Warning Pending issuer.certmanager.k8s.io \"fake-issuer\" not found"},
			},
		},
		"exit nil if we cannot determine the issuer type (probably not meant for us)": {
			certificateRequest: exampleCR,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, errors.New("unexpected sign call")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test"),
					gen.Issuer("fake-issuer",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmapi.ConditionTrue,
						}),
						// no issuer set
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleCRIssuerNotFoundPendingCondition,
					)),
				},
				ExpectedEvents: []string{"Warning Pending no issuer specified for Issuer 'default-unit-test-ns/fake-issuer'"},
			},
		},
		"exit nil if the issuer type is not meant for us": {
			certificateRequest: exampleCRWrongIssuerRefType,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, errors.New("unexpected sign call")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test"),
					gen.Issuer("selfsigned-issuer",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmapi.ConditionTrue,
						}),
						gen.SetIssuerCA(cmapi.CAIssuer{SecretName: "fake-root-ca"}),
					),
				},
				ExpectedActions: []testpkg.Action{},
			},
		},
		"exit if we fail validation during a sync": {
			certificateRequest: exampleEmptyCSRCR,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, errors.New("unexpected sign call")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test"),
					gen.Issuer("fake-issuer",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmapi.ConditionTrue,
						}),
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleFailedValidationCR,
					)),
				},
				ExpectedEvents: []string{"Warning BadConfig Resource validation failed: spec.csr: Required value: must be specified"},
			},
		},
		"should exit sync nil if condition is failed": {
			certificateRequest: exampleFailedCR,
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, errors.New("unexpected sign call")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.CertificateRequest("test"),
					gen.Issuer("fake-issuer",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmapi.ConditionTrue,
						}),
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
					),
				},
				ExpectedActions: []testpkg.Action{}, // no update
			},
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			fixedClock.SetTime(nowTime)
			test.builder.Clock = fixedClock
			runTest(t, test)
		})
	}
}

type testT struct {
	builder            *testpkg.Builder
	issuerImpl         Issuer
	certificateRequest *cmapi.CertificateRequest
	expectedErr        bool
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Start()
	defer test.builder.Stop()

	c := &Controller{
		issuerType: util.IssuerSelfSigned,
		issuer:     test.issuerImpl,
	}
	c.Register(test.builder.Context)
	test.builder.Sync()

	err := c.Sync(context.Background(), test.certificateRequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}
	test.builder.CheckAndFinish(err)
}
