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
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientcorev1 "k8s.io/client-go/listers/core/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/pointer"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests/util"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
	listersfake "github.com/jetstack/cert-manager/test/unit/listers"
	testlisters "github.com/jetstack/cert-manager/test/unit/listers"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func generateCSR(t *testing.T, secretKey crypto.Signer, alg x509.SignatureAlgorithm, commonName string) []byte {
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: commonName,
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
	csrRSAPEM := generateCSR(t, skRSA, x509.SHA256WithRSA, "test-rsa")

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
	csrECPEM := generateCSR(t, skEC, x509.ECDSAWithSHA256, "test-ec")

	csrEmptyCertPEM := generateCSR(t, skEC, x509.ECDSAWithSHA256, "")

	baseCRNotApproved := gen.CertificateRequest("test-cr",
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
	baseCRDenied := gen.CertificateRequestFrom(baseCRNotApproved,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionDenied,
			Status:             cmmeta.ConditionTrue,
			Reason:             "Foo",
			Message:            "Certificate request has been denied by cert-manager.io",
			LastTransitionTime: &metaFixedClockStart,
		}),
	)
	baseCR := gen.CertificateRequestFrom(baseCRNotApproved,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionApproved,
			Status:             cmmeta.ConditionTrue,
			Reason:             "cert-manager.io",
			Message:            "Certificate request has been approved by cert-manager.io",
			LastTransitionTime: &metaFixedClockStart,
		}),
	)
	ecCR := gen.CertificateRequestFrom(baseCR,
		gen.SetCertificateRequestCSR(csrECPEM),
	)
	emptyCR := gen.CertificateRequestFrom(baseCR,
		gen.SetCertificateRequestCSR(csrEmptyCertPEM),
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

	templateEmptyCert, err := pki.GenerateTemplateFromCertificateRequest(emptyCR)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	emptyCertPEM, _, err := pki.SignCertificate(templateEmptyCert, templateEmptyCert, skEC.Public(), skEC)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	tests := map[string]testT{
		"a CertificateRequest without an approved condition should do nothing": {
			certificateRequest: baseCRNotApproved.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCRNotApproved.DeepCopy(), baseIssuer.DeepCopy()},
			},
		},
		"a CertificateRequest with a denied condition should update Ready condition with 'Denied'": {
			certificateRequest: baseCRDenied.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCRDenied.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents:     []string{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCRDenied,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Denied",
								Message:            "The CertificateRequest was denied by an approval controller",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
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
		"should sign a cert with no subject DN and create a warning event": {
			certificateRequest: emptyCR.DeepCopy(),
			signingFn: func(c1 *x509.Certificate, c2 *x509.Certificate, pk crypto.PublicKey, sk interface{}) ([]byte, *x509.Certificate, error) {
				_, cert, err := pki.SignCertificate(c1, c2, pk, sk)
				if err != nil {
					return nil, nil, err
				}

				if cert.Subject.String() != "" {
					return nil, nil, errors.New("invalid test: cert being issued should have an empty DN")
				}

				// need to return a known PEM cert as is done in other tets, since the actual issued cert (`cert` above)
				// will have a different serial number + expiry
				return emptyCertPEM, nil, nil
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{ecKeySecret},
				CertManagerObjects: []runtime.Object{emptyCR.DeepCopy(), baseIssuer},
				ExpectedEvents: []string{
					fmt.Sprintf("Warning BadConfig %s", emptyDNMessage),
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(
							emptyCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(emptyCertPEM),
							gen.SetCertificateRequestCA(emptyCertPEM),
						),
					)),
				},
			},
		},
		"should mark a CertificateRequest as failed if maxPathLen is set on the Issuer, but not isCA": {
			certificateRequest: emptyCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{ecKeySecret},
				CertManagerObjects: []runtime.Object{emptyCR.DeepCopy(), gen.IssuerFrom(baseIssuer,
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{
						PathLen: pointer.Int(5),
					}),
				)},
				ExpectedEvents: []string{
					"Warning ErrorSigning Error signing certificate: issuer requires the isCA field to be present to sign certificates as it has configured pathLen, pathLen=5 isCA=false",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(emptyCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Error signing certificate: issuer requires the isCA field to be present to sign certificates as it has configured pathLen, pathLen=5 isCA=false",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
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

func TestSelfSigned_Sign(t *testing.T) {
	sk, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	skPEM, err := pki.EncodeECPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}

	testCSR := generateCSR(t, sk, x509.ECDSAWithSHA256, "test-common-name")

	tests := map[string]struct {
		givenSelfSignedSecret *corev1.Secret
		givenSelfSignedIssuer cmapi.GenericIssuer
		givenCR               *cmapi.CertificateRequest
		assertSignedCert      func(t *testing.T, got *x509.Certificate)
		wantErr               string
	}{
		"when the CertificateRequest has the duration field set, it should appear as notAfter on the signed certificate": {
			givenSelfSignedSecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"),
				gen.SetSecretData(map[string][]byte{
					"tls.key": skPEM,
				}),
			),
			givenSelfSignedIssuer: gen.Issuer("issuer-1",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestAnnotations(map[string]string{
					cmapi.CertificateRequestPrivateKeyAnnotationKey: "secret-1",
				}),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
				gen.SetCertificateRequestDuration(&metav1.Duration{
					Duration: 30 * time.Minute,
				}),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				// Although there is less than 1µs between the time.Now
				// call made by the certificate template func (in the "pki"
				// package) and the time.Now below, rounding or truncating
				// will always end up with a flaky test. This is due to the
				// rounding made to the notAfter value when serializing the
				// certificate to ASN.1 [1].
				//
				//  [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
				//
				// So instead of using a truncation or rounding in order to
				// check the time, we use a delta of 1 second. One entire
				// second is totally overkill since, as detailed above, the
				// delay is probably less than a microsecond. But that will
				// do for now!
				//
				// Note that we do have a plan to fix this. We want to be
				// injecting a time (instead of time.Now) to the template
				// functions. This work is being tracked in this issue:
				// https://github.com/jetstack/cert-manager/issues/3738
				expectNotAfter := time.Now().UTC().Add(30 * time.Minute)
				deltaSec := math.Abs(expectNotAfter.Sub(got.NotAfter).Seconds())
				assert.LessOrEqualf(t, deltaSec, 1., "expected a time delta lower than 1 second. Time expected='%s', got='%s'", expectNotAfter.String(), got.NotAfter.String())
				assert.Equal(t, false, got.IsCA)
				assert.Equal(t, -1, got.MaxPathLen)
				assert.Equal(t, false, got.MaxPathLenZero)
			},
		},
		"when the CertificateRequest has the isCA field set, it should appear on the signed ca": {
			givenSelfSignedSecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"),
				gen.SetSecretData(map[string][]byte{
					"tls.key": skPEM,
				}),
			),
			givenSelfSignedIssuer: gen.Issuer("issuer-1",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestAnnotations(map[string]string{
					cmapi.CertificateRequestPrivateKeyAnnotationKey: "secret-1",
				}),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
				gen.SetCertificateRequestIsCA(true),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, true, got.IsCA)
				assert.Equal(t, -1, got.MaxPathLen)
				assert.Equal(t, false, got.MaxPathLenZero)
			},
		},
		"when the Issuer has crlDistributionPoints set, it should appear on the signed certificate": {
			givenSelfSignedSecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"),
				gen.SetSecretData(map[string][]byte{
					"tls.key": skPEM,
				}),
			),
			givenSelfSignedIssuer: gen.Issuer("issuer-1",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{
					CRLDistributionPoints: []string{"http://www.example.com/crl/test.crl"},
				}),
			),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestAnnotations(map[string]string{
					cmapi.CertificateRequestPrivateKeyAnnotationKey: "secret-1",
				}),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, []string{"http://www.example.com/crl/test.crl"}, got.CRLDistributionPoints)
				assert.Equal(t, false, got.IsCA)
				assert.Equal(t, -1, got.MaxPathLen)
				assert.Equal(t, false, got.MaxPathLenZero)
			},
		},
		"when the Issuer has pathLen set to 5, it should appear on the signed certificate": {
			givenSelfSignedSecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"),
				gen.SetSecretData(map[string][]byte{
					"tls.key": skPEM,
				}),
			),
			givenSelfSignedIssuer: gen.Issuer("issuer-1",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{
					PathLen: pointer.Int(5),
				}),
			),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestAnnotations(map[string]string{
					cmapi.CertificateRequestPrivateKeyAnnotationKey: "secret-1",
				}),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
				gen.SetCertificateRequestIsCA(true),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, true, got.IsCA)
				assert.Equal(t, 5, got.MaxPathLen)
				assert.Equal(t, false, got.MaxPathLenZero)
			},
		},
		"when the Issuer has pathLen set to 0, it should appear on the signed certificate": {
			givenSelfSignedSecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"),
				gen.SetSecretData(map[string][]byte{
					"tls.key": skPEM,
				}),
			),
			givenSelfSignedIssuer: gen.Issuer("issuer-1",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{
					PathLen: pointer.Int(0),
				}),
			),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestAnnotations(map[string]string{
					cmapi.CertificateRequestPrivateKeyAnnotationKey: "secret-1",
				}),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
				gen.SetCertificateRequestIsCA(true),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, true, got.IsCA)
				assert.Equal(t, 0, got.MaxPathLen)
				assert.Equal(t, true, got.MaxPathLenZero)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &testpkg.FakeRecorder{}

			iss := &SelfSigned{
				reporter: util.NewReporter(fixedClock, rec),
				recorder: rec,
				secretsLister: testlisters.FakeSecretListerFrom(testlisters.NewFakeSecretLister(),
					testlisters.SetFakeSecretNamespaceListerGet(test.givenSelfSignedSecret, nil),
				),
				signingFn: pki.SignCertificate,
			}

			gotIssueResp, gotErr := iss.Sign(context.Background(), test.givenCR, test.givenSelfSignedIssuer)
			if test.wantErr != "" {
				require.EqualError(t, gotErr, test.wantErr)
			} else {
				require.NoError(t, gotErr)

				require.NotNil(t, gotIssueResp)
				gotCert, err := pki.DecodeX509CertificateBytes(gotIssueResp.Certificate)
				require.NoError(t, err)

				test.assertSignedCert(t, gotCert)
			}
		})
	}
}
