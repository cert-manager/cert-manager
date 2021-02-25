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

package selfsigned

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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientcorev1 "k8s.io/client-go/listers/core/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	listersfake "github.com/cert-manager/cert-manager/test/unit/listers"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func generateCSR(t *testing.T, secretKey crypto.Signer, alg x509.SignatureAlgorithm) []byte {
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "test",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
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
	metaFixedClockStart := metav1.NewTime(fixedClockStart)

	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	skRSA, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate RSA private key: %s", err)
		t.FailNow()
	}
	skRSAPEM := pki.EncodePKCS1PrivateKey(skRSA)
	rsaKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rsa-key",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: skRSAPEM,
		},
	}
	invalidKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rsaKeySecret.Name,
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: []byte("this is a bad key"),
		},
	}
	csrRSAPEM := generateCSR(t, skRSA, x509.SHA256WithRSA)

	skEC, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Errorf("failed to generate ECDA private key: %s", err)
		t.FailNow()
	}
	skECPEM, err := pki.EncodeECPrivateKey(skEC)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	ecKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rsaKeySecret.Name,
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: skECPEM,
		},
	}
	csrECPEM := generateCSR(t, skEC, x509.ECDSAWithSHA256)

	baseCR := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestAnnotations(
			map[string]string{
				cmapi.CertificateRequestPrivateKeyAnnotationKey: rsaKeySecret.Name,
			},
		),
		gen.SetCertificateRequestCSR(csrRSAPEM),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name:  baseIssuer.Name,
			Group: certmanager.GroupName,
			Kind:  "Issuer",
		}),
	)
	ecCR := gen.CertificateRequestFrom(baseCR,
		gen.SetCertificateRequestCSR(csrECPEM),
	)

	templateRSA, err := pki.GenerateTemplateFromCertificateRequest(baseCR)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	certRSAPEM, _, err := pki.SignCertificate(templateRSA, templateRSA, skRSA.Public(), skRSA)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	templateEC, err := pki.GenerateTemplateFromCertificateRequest(ecCR)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	certECPEM, _, err := pki.SignCertificate(templateEC, templateEC, skEC.Public(), skEC)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	tests := map[string]testT{
		"a CertificateRequest with no cert-manager.io/selfsigned-private-key annotation should fail": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				// no annotation
				gen.DeleteCertificateRequestAnnotation(cmapi.CertificateRequestPrivateKeyAnnotationKey),
			),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{gen.CertificateRequestFrom(baseCR,
					// no annotation
					gen.DeleteCertificateRequestAnnotation(cmapi.CertificateRequestPrivateKeyAnnotationKey),
				), baseIssuer},
				ExpectedEvents: []string{
					`Warning MissingAnnotation Annotation "cert-manager.io/private-key-secret-name" missing or reference empty: secret name missing`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.DeleteCertificateRequestAnnotation(cmapi.CertificateRequestPrivateKeyAnnotationKey),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            `Annotation "cert-manager.io/private-key-secret-name" missing or reference empty: secret name missing`,
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"a CertificateRequest with a cert-manager.io/private-key-secret-name annotation but empty string should fail": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				// no data in annotation
				gen.SetCertificateRequestAnnotations(map[string]string{cmapi.CertificateRequestPrivateKeyAnnotationKey: ""}),
			),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{gen.CertificateRequestFrom(baseCR,
					// no data in annotation
					gen.SetCertificateRequestAnnotations(map[string]string{cmapi.CertificateRequestPrivateKeyAnnotationKey: ""}),
				), baseIssuer},
				ExpectedEvents: []string{
					`Warning MissingAnnotation Annotation "cert-manager.io/private-key-secret-name" missing or reference empty: secret name missing`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestAnnotations(map[string]string{cmapi.CertificateRequestPrivateKeyAnnotationKey: ""}),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            `Annotation "cert-manager.io/private-key-secret-name" missing or reference empty: secret name missing`,
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"if the referenced secret doesn't exist then should record pending": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer},
				ExpectedEvents: []string{
					`Normal MissingSecret Referenced secret default-unit-test-ns/test-rsa-key not found: secret "test-rsa-key" not found`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Referenced secret default-unit-test-ns/test-rsa-key not found: secret "test-rsa-key" not found`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"if the referenced secret contains invalid data then should record pending": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{invalidKeySecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer},
				ExpectedEvents: []string{
					`Normal ErrorParsingKey Failed to get key "test-rsa-key" referenced in annotation "cert-manager.io/private-key-secret-name": error decoding private key PEM block`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Failed to get key "test-rsa-key" referenced in annotation "cert-manager.io/private-key-secret-name": error decoding private key PEM block`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"should exit nil and set status pending if referenced issuer is not ready": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(),
					gen.Issuer(baseIssuer.DeepCopy().Name,
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
					)},
				ExpectedEvents: []string{
					"Normal IssuerNotReady Referenced issuer does not have a Ready status condition",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Pending",
								Message:            "Referenced issuer does not have a Ready status condition",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a CertificateRequest that transiently fails a secret lookup should backoff error to retry": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaKeySecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer},
				ExpectedEvents: []string{
					`Normal ErrorGettingSecret Failed to get certificate key pair from secret default-unit-test-ns/test-rsa-key: this is a network error`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to get certificate key pair from secret default-unit-test-ns/test-rsa-key: this is a network error",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeLister: &listersfake.FakeSecretLister{
				SecretsFn: func(namespace string) clientcorev1.SecretNamespaceLister {
					return &listersfake.FakeSecretNamespaceLister{
						GetFn: func(name string) (ret *corev1.Secret, err error) {
							return nil, errors.New("this is a network error")
						},
					}
				},
			},
			expectedErr: true,
		},
		"a CertificateRequest with a bad CSR should fail": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestCSR([]byte("this is a bad CSR")),
			),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{rsaKeySecret},
				CertManagerObjects: []runtime.Object{gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestCSR([]byte("this is a bad CSR")),
				), baseIssuer},
				ExpectedEvents: []string{
					"Warning BadConfig Resource validation failed: spec.request: Invalid value: []byte{0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x62, 0x61, 0x64, 0x20, 0x43, 0x53, 0x52}: failed to decode csr: error decoding certificate request PEM block",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCSR([]byte("this is a bad CSR")),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Resource validation failed: spec.request: Invalid value: []byte{0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x62, 0x61, 0x64, 0x20, 0x43, 0x53, 0x52}: failed to decode csr: error decoding certificate request PEM block",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"a CSR that has not been signed with the same public key as the referenced private key should fail": {
			certificateRequest: ecCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaKeySecret},
				CertManagerObjects: []runtime.Object{ecCR.DeepCopy(), baseIssuer},
				ExpectedEvents: []string{
					"Warning ErrorKeyMatch Error generating certificate template: CSR not signed by referenced private key",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(ecCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Error generating certificate template: CSR not signed by referenced private key",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"if signing fails then should report failure": {
			certificateRequest: baseCR.DeepCopy(),
			signingFn: func(*x509.Certificate, *x509.Certificate, crypto.PublicKey, interface{}) ([]byte, *x509.Certificate, error) {
				return nil, nil, errors.New("this is a signing error")
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaKeySecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer},
				ExpectedEvents: []string{
					"Warning ErrorSigning Error signing certificate: this is a signing error",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Error signing certificate: this is a signing error",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"should sign an RSA key set condition to Ready": {
			certificateRequest: baseCR.DeepCopy(),
			signingFn: func(c1 *x509.Certificate, c2 *x509.Certificate, pk crypto.PublicKey, sk interface{}) ([]byte, *x509.Certificate, error) {
				// We still check that it will sign and not error
				// Return error if we do
				_, _, err := pki.SignCertificate(c1, c2, pk, sk)
				if err != nil {
					return nil, nil, err
				}

				return certRSAPEM, nil, nil
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaKeySecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(certRSAPEM),
							gen.SetCertificateRequestCA(certRSAPEM),
						),
					)),
				},
			},
		},
		"should sign an EC key set condition to Ready": {
			certificateRequest: ecCR.DeepCopy(),
			signingFn: func(c1 *x509.Certificate, c2 *x509.Certificate, pk crypto.PublicKey, sk interface{}) ([]byte, *x509.Certificate, error) {
				// We still check that it will sign and not error
				// Return error if we do
				_, _, err := pki.SignCertificate(c1, c2, pk, sk)
				if err != nil {
					return nil, nil, err
				}

				return certECPEM, nil, nil
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{ecKeySecret},
				CertManagerObjects: []runtime.Object{ecCR.DeepCopy(), baseIssuer},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(ecCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(certECPEM),
							gen.SetCertificateRequestCA(certECPEM),
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
	signingFn          signingFn

	expectedErr bool

	fakeLister *listersfake.FakeSecretLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	self := NewSelfSigned(test.builder.Context)

	if test.fakeLister != nil {
		self.secretsLister = test.fakeLister
	}

	if test.signingFn != nil {
		self.signingFn = test.signingFn
	}

	controller := certificaterequests.New(apiutil.IssuerSelfSigned, self)
	controller.Register(test.builder.Context)
	test.builder.Start()

	err := controller.Sync(context.Background(), test.certificateRequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}
