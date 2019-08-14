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

package ca

import (
	"bytes"
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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientcorev1 "k8s.io/client-go/listers/core/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
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

func generateSelfSignedCertFromCR(t *testing.T, cr *cmapi.CertificateRequest, key crypto.Signer,
	duration time.Duration) (*x509.Certificate, []byte) {
	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		t.Errorf("error generating template: %v", err)
	}

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

	return template, pemByteBuffer.Bytes()
}

func TestSign(t *testing.T) {
	// Build root RSA CA
	rsaPK, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	rsaPKBytes := pki.EncodePKCS1PrivateKey(rsaPK)

	caCSR := generateCSR(t, rsaPK)

	rootRSACR := gen.CertificateRequest("test-root-ca",
		gen.SetCertificateRequestCSR(caCSR),
		gen.SetCertificateRequestIsCA(true),
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
	)

	// generate a self signed root ca valid for 60d
	rsaCert, rsaPEMCert := generateSelfSignedCertFromCR(t, rootRSACR, rsaPK, time.Hour*24*60)
	rootRSACASecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root-ca-secret",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: rsaPKBytes,
			corev1.TLSCertKey:       rsaPEMCert,
		},
	}

	rootRSANoCASecret := rootRSACASecret.DeepCopy()
	rootRSANoCASecret.Data[corev1.TLSCertKey] = make([]byte, 0)
	rootRSANoKeySecret := rootRSACASecret.DeepCopy()
	rootRSANoKeySecret.Data[corev1.TLSPrivateKeyKey] = make([]byte, 0)

	basicIssuer := gen.Issuer("ca-issuer",
		gen.SetIssuerCA(cmapi.CAIssuer{SecretName: "root-ca-secret"}),
	)

	validCR := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestIsCA(true),
		gen.SetCertificateRequestCSR(caCSR),
		gen.SetCertificateRequestIssuer(cmapi.ObjectReference{
			Name:  basicIssuer.Name,
			Group: certmanager.GroupName,
			Kind:  "Issuer",
		}),
	)

	template, err := pki.GenerateTemplateFromCertificateRequest(validCR)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	certPEM, _, err := pki.SignCSRTemplate([]*x509.Certificate{rsaCert}, rsaPK, template)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	tests := map[string]testT{
		"fail to find CA tls key pair": {
			certificateRequest: validCR,
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{validCR.DeepCopy(), basicIssuer},
				ExpectedEvents: []string{
					`Normal MissingSecret Referenced secret default-unit-test-ns/root-ca-secret not found: secret "root-ca-secret" not found`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(validCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Certificate issuance pending",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			expectedErr: false,
		},
		"given bad CSR should fail Certificate generation": {
			certificateRequest: gen.CertificateRequestFrom(validCR,
				gen.SetCertificateRequestCSR([]byte("bad-csr")),
			),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rootRSACASecret},
				CertManagerObjects: []runtime.Object{validCR.DeepCopy(), basicIssuer},
				ExpectedEvents: []string{
					"Warning BadConfig Resource validation failed: spec.csr: Invalid value: []byte{0x62, 0x61, 0x64, 0x2d, 0x63, 0x73, 0x72}: failed to decode csr: error decoding certificate request PEM block",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(validCR,
							gen.SetCertificateRequestCSR([]byte("bad-csr")),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Resource validation failed: spec.csr: Invalid value: []byte{0x62, 0x61, 0x64, 0x2d, 0x63, 0x73, 0x72}: failed to decode csr: error decoding certificate request PEM block",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			expectedErr: false,
		},
		"no CA certificate should fail a signing": {
			certificateRequest: validCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rootRSANoCASecret},
				CertManagerObjects: []runtime.Object{validCR.DeepCopy(), basicIssuer},
				ExpectedEvents: []string{
					`Normal ErrorParsingSecret Failed to parse signing CA keypair from secret default-unit-test-ns/root-ca-secret: error decoding cert PEM block`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(validCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Certificate issuance pending",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			expectedErr: false,
		},
		"no CA key should fail a signing": {
			certificateRequest: validCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rootRSANoKeySecret},
				CertManagerObjects: []runtime.Object{validCR.DeepCopy(), basicIssuer},
				ExpectedEvents: []string{
					`Normal ErrorParsingSecret Failed to parse signing CA keypair from secret default-unit-test-ns/root-ca-secret: error decoding private key PEM block`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(validCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Certificate issuance pending",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			expectedErr: false,
		},
		"a CertificateRequest that transiently fails a secret lookup should backoff error to retry": {
			certificateRequest: validCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rootRSACASecret},
				CertManagerObjects: []runtime.Object{validCR.DeepCopy(), basicIssuer},
				ExpectedEvents: []string{
					`Normal ErrorGettingSecret Failed to get certificate key pair from secret default-unit-test-ns/root-ca-secret: this is a network error`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(validCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Certificate issuance pending",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeLister: &testlisters.FakeSecretLister{
				SecretsFn: func(namespace string) clientcorev1.SecretNamespaceLister {
					return &testlisters.FakeSecretNamespaceLister{
						GetFn: func(name string) (ret *corev1.Secret, err error) {
							return nil, errors.New("this is a network error")
						},
					}
				},
			},
			expectedErr: true,
		},
		"sign a CertificateRequest": {
			certificateRequest: validCR.DeepCopy(),
			templateGenerator: func(cr *cmapi.CertificateRequest) (*x509.Certificate, error) {
				_, err := pki.GenerateTemplateFromCertificateRequest(cr)
				if err != nil {
					return nil, err
				}

				return template, nil
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rootRSACASecret},
				CertManagerObjects: []runtime.Object{validCR.DeepCopy(), basicIssuer},
				ExpectedEvents: []string{
					`Normal Issued Certificate fetched from issuer successfully`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(validCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmapi.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate has been issued successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCA(rsaPEMCert),
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

	templateGenerator templateGenerator

	expectedErr bool

	fakeLister *testlisters.FakeSecretLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Start()
	defer test.builder.Stop()

	ca := NewCA(test.builder.Context)

	if test.fakeLister != nil {
		ca.secretsLister = test.fakeLister
	}

	if test.templateGenerator != nil {
		ca.templateGenerator = test.templateGenerator
	}

	controller := certificaterequests.New(apiutil.IssuerCA, ca)
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
