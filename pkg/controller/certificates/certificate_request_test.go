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

package certificates

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

type cryptoBundle struct {
	// certificate is the Certificate resource used to create this bundle
	certificate *cmapi.Certificate
	// expectedRequestName is the name of the CertificateRequest that is
	// expected to be created to issue this certificate
	expectedRequestName string

	// privateKey is the private key used as the complement to the certificates
	// in this bundle
	privateKey      crypto.Signer
	privateKeyBytes []byte

	// csr is the CSR used to obtain the certificate in this bundle
	csr      *x509.CertificateRequest
	csrBytes []byte

	// certificateRequest is the request that is expected to be created to
	// obtain a certificate when using this bundle
	certificateRequest       *cmapi.CertificateRequest
	certificateRequestReady  *cmapi.CertificateRequest
	certificateRequestFailed *cmapi.CertificateRequest

	// cert is a signed certificate
	cert      *x509.Certificate
	certBytes []byte

	localTemporaryCertificateBytes []byte
}

func mustCreateCryptoBundle(t *testing.T, crt *cmapi.Certificate) cryptoBundle {
	c, err := createCryptoBundle(crt)
	if err != nil {
		t.Fatalf("error generating crypto bundle: %v", err)
	}
	return *c
}

func createCryptoBundle(crt *cmapi.Certificate) (*cryptoBundle, error) {
	reqName, err := expectedCertificateRequestName(crt)
	if err != nil {
		return nil, err
	}

	privateKey, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := pki.EncodePrivateKey(privateKey, crt.Spec.KeyEncoding)
	if err != nil {
		return nil, err
	}

	csrPEM, err := generateCSRImpl(crt, privateKeyBytes)
	if err != nil {
		return nil, err
	}

	csr, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		return nil, err
	}

	certificateRequest := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:            reqName,
			Namespace:       crt.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
			Annotations: map[string]string{
				cmapi.CRPrivateKeyAnnotationKey: crt.Spec.SecretName,
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			CSRPEM:    csrPEM,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
		},
	}

	unsignedCert, err := pki.GenerateTemplateFromCertificateRequest(certificateRequest)
	if err != nil {
		return nil, err
	}

	certBytes, cert, err := pki.SignCertificate(unsignedCert, unsignedCert, privateKey.Public(), privateKey)
	if err != nil {
		return nil, err
	}

	certificateRequestReady := gen.CertificateRequestFrom(certificateRequest,
		gen.SetCertificateRequestCertificate(certBytes),
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmapi.ConditionTrue,
			Reason: cmapi.CertificateRequestReasonIssued,
		}),
	)

	certificateRequestFailed := gen.CertificateRequestFrom(certificateRequest,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmapi.ConditionFalse,
			Reason: cmapi.CertificateRequestReasonFailed,
		}),
	)

	tempCertBytes, err := generateLocallySignedTemporaryCertificate(crt, privateKeyBytes)
	if err != nil {
		panic("failed to generate test fixture: " + err.Error())
	}

	return &cryptoBundle{
		certificate:                    crt,
		expectedRequestName:            reqName,
		privateKey:                     privateKey,
		privateKeyBytes:                privateKeyBytes,
		csr:                            csr,
		csrBytes:                       csrPEM,
		certificateRequest:             certificateRequest,
		certificateRequestReady:        certificateRequestReady,
		certificateRequestFailed:       certificateRequestFailed,
		cert:                           cert,
		certBytes:                      certBytes,
		localTemporaryCertificateBytes: tempCertBytes,
	}, nil
}

func (c *cryptoBundle) generateTestCSR(crt *cmapi.Certificate) []byte {
	csrPEM, err := generateCSRImpl(crt, c.privateKeyBytes)
	if err != nil {
		panic("failed to generate test fixture: " + err.Error())
	}

	return csrPEM
}

func (c *cryptoBundle) generateTestCertificate(crt *cmapi.Certificate, notBefore *time.Time) []byte {
	csr := c.generateTestCSR(crt)
	certificateRequest := &cmapi.CertificateRequest{
		Spec: cmapi.CertificateRequestSpec{
			CSRPEM:    csr,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
		},
	}

	unsignedCert, err := pki.GenerateTemplateFromCertificateRequest(certificateRequest)
	if err != nil {
		panic("failed to generate test fixture: " + err.Error())
	}

	if notBefore != nil {
		unsignedCert.NotBefore = *notBefore
	}

	certBytes, _, err := pki.SignCertificate(unsignedCert, unsignedCert, c.privateKey.Public(), c.privateKey)
	if err != nil {
		panic("failed to generate test fixture: " + err.Error())
	}

	return certBytes
}

func (c *cryptoBundle) generateCertificateExpiring1H(crt *cmapi.Certificate) []byte {
	csr := c.generateTestCSR(crt)
	certificateRequest := &cmapi.CertificateRequest{
		Spec: cmapi.CertificateRequestSpec{
			CSRPEM:    csr,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
		},
	}

	unsignedCert, err := pki.GenerateTemplateFromCertificateRequest(certificateRequest)
	if err != nil {
		panic("failed to generate test fixture: " + err.Error())
	}

	nowTime := fixedClock.Now()
	duration := unsignedCert.NotAfter.Sub(unsignedCert.NotBefore)
	unsignedCert.NotBefore = nowTime.Add(time.Hour).Add(-1 * duration)
	unsignedCert.NotAfter = nowTime.Add(time.Hour)

	certBytes, _, err := pki.SignCertificate(unsignedCert, unsignedCert, c.privateKey.Public(), c.privateKey)
	if err != nil {
		panic("failed to generate test fixture: " + err.Error())
	}

	return certBytes
}

func (c *cryptoBundle) generateCertificateExpired(crt *cmapi.Certificate) []byte {
	csr := c.generateTestCSR(crt)
	certificateRequest := &cmapi.CertificateRequest{
		Spec: cmapi.CertificateRequestSpec{
			CSRPEM:    csr,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
		},
	}

	unsignedCert, err := pki.GenerateTemplateFromCertificateRequest(certificateRequest)
	if err != nil {
		panic("failed to generate test fixture: " + err.Error())
	}

	nowTime := fixedClock.Now()
	duration := unsignedCert.NotAfter.Sub(unsignedCert.NotBefore)
	unsignedCert.NotBefore = nowTime.Add(-1 * time.Hour).Add(-1 * duration)
	unsignedCert.NotAfter = nowTime.Add(-1 * time.Hour)

	certBytes, _, err := pki.SignCertificate(unsignedCert, unsignedCert, c.privateKey.Public(), c.privateKey)
	if err != nil {
		panic("failed to generate test fixture: " + err.Error())
	}

	return certBytes
}

func (c *cryptoBundle) generateCertificateTemporary(crt *cmapi.Certificate) []byte {
	d, err := generateLocallySignedTemporaryCertificate(crt, c.privateKeyBytes)
	if err != nil {
		panic("failed to generate test fixture: " + err.Error())
	}
	return d
}

func certificateNotAfter(b []byte) time.Time {
	cert, err := pki.DecodeX509CertificateBytes(b)
	if err != nil {
		panic("failed to decode certificate: " + err.Error())
	}
	return cert.NotAfter
}

func testGeneratePrivateKeyBytesFn(b []byte) generatePrivateKeyBytesFn {
	return func(context.Context, *cmapi.Certificate) ([]byte, error) {
		return b, nil
	}
}

func testGenerateCSRFn(b []byte) generateCSRFn {
	return func(_ *cmapi.Certificate, _ []byte) ([]byte, error) {
		return b, nil
	}
}

func testLocalTemporarySignerFn(b []byte) localTemporarySignerFn {
	return func(crt *cmapi.Certificate, pk []byte) ([]byte, error) {
		return b, nil
	}
}

func TestBuildCertificateRequest(t *testing.T) {
	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmapi.ObjectReference{Name: "ca-issuer", Kind: "Issuer", Group: "not-empty"}),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(time.Hour*36),
		gen.SetCertificateDNSNames("example.com"),
	)
	exampleBundle := mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
		gen.SetCertificateDNSNames("example.com"),
	))

	tests := map[string]struct {
		crt         *cmapi.Certificate
		name        string
		pk          []byte
		expectedErr bool

		expectedCertificateRequestAnnotations map[string]string
	}{
		"a bad private key should error": {
			crt:         baseCert,
			pk:          []byte("bad key"),
			name:        "test",
			expectedErr: true,

			expectedCertificateRequestAnnotations: nil,
		},
		"a good certificate should always have annotations set": {
			crt:         baseCert,
			pk:          exampleBundle.privateKeyBytes,
			name:        "test",
			expectedErr: false,

			expectedCertificateRequestAnnotations: map[string]string{
				cmapi.CRPrivateKeyAnnotationKey: baseCert.Spec.SecretName,
			},
		},
	}

	for name, test := range tests {
		c := &certificateRequestManager{
			generateCSR: generateCSRImpl,
		}

		cr, err := c.buildCertificateRequest(nil, test.crt, test.name, test.pk)
		if err != nil && !test.expectedErr {
			t.Errorf("expected no error but got: %s", err)
		}

		if err == nil && test.expectedErr {
			t.Error("expected and error but got 'nil'")
		}

		if cr == nil {
			continue
		}

		// check for annotations
		if !reflect.DeepEqual(cr.Annotations, test.expectedCertificateRequestAnnotations) {
			t.Errorf("%s: got unexpected resulting certificate request annotations, exp=%+v got=%+v",
				name, test.expectedCertificateRequestAnnotations, cr.Annotations)
		}
	}
}

func TestProcessCertificate(t *testing.T) {
	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmapi.ObjectReference{Name: "test", Kind: "something", Group: "not-empty"}),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(time.Hour*36),
	)
	exampleBundle1 := mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
		gen.SetCertificateDNSNames("example.com"),
	))
	exampleECBundle := mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
		gen.SetCertificateDNSNames("example.com"),
		gen.SetCertificateKeyAlgorithm(cmapi.ECDSAKeyAlgorithm),
	))

	tests := map[string]testT{
		"generate a private key and create a new secret if one does not exist": {
			certificate:             exampleBundle1.certificate,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle1.privateKeyBytes),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       nil,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{"Normal GeneratedKey Generated a new private key"},
			},
		},
		"generate a private key and update an existing secret if one already exists": {
			certificate:             exampleBundle1.certificate,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle1.privateKeyBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation": "value",
							},
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       nil,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{"Normal GeneratedKey Generated a new private key"},
			},
		},
		"generate a new private key and update the Secret if the existing private key data is garbage": {
			certificate:             exampleBundle1.certificate,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle1.privateKeyBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation": "value",
							},
						},
						Type: corev1.SecretTypeTLS,
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: []byte("invalid"),
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       nil,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{`Normal GeneratedKey Generated a new private key`},
			},
		},
		"generate a new private key and update the Secret if the existing private key data has a differing keyAlgorithm": {
			certificate:             exampleBundle1.certificate,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle1.privateKeyBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation": "value",
							},
						},
						Type: corev1.SecretTypeTLS,
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleECBundle.privateKeyBytes,
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       nil,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{"Normal GeneratedKey Generated a new private key"},
			},
		},
		"create a new certificatesigningrequest resource if the secret contains a private key but no certificate": {
			certificate: exampleBundle1.certificate,
			generateCSR: testGenerateCSRFn(exampleBundle1.csrBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       nil,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleBundle1.certificateRequest,
					)),
				},
				ExpectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-850937773"`},
			},
		},
		"delete an existing certificaterequest that does not have matching dnsnames": {
			certificate: exampleBundle1.certificate,
			generateCSR: testGenerateCSRFn(exampleBundle1.csrBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       nil,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					gen.CertificateRequestFrom(exampleBundle1.certificateRequest,
						gen.SetCertificateRequestName("not-expected-name"),
						gen.SetCertificateRequestCSR(
							exampleBundle1.generateTestCSR(gen.CertificateFrom(exampleBundle1.certificate,
								gen.SetCertificateDNSNames("notexample.com"),
							)),
						),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						"not-expected-name",
					)),
					testpkg.NewAction(coretesting.NewCreateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleBundle1.certificateRequest,
					)),
				},
				ExpectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-850937773"`},
			},
		},
		"do nothing and wait if an up to date certificaterequest resource exists and is not Ready": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: "Issuer",
								cmapi.IssuerNameAnnotationKey: "test",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       nil,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequest,
				},
			},
		},
		"create a new CertificateRequest if existing Certificate expires soon": {
			certificate: exampleBundle1.certificate,
			generateCSR: testGenerateCSRFn(exampleBundle1.csrBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IPSANAnnotationKey:      "",
								cmapi.AltNamesAnnotationKey:   "example.com",
								cmapi.CommonNameAnnotationKey: "example.com",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundle1.generateCertificateExpiring1H(exampleBundle1.certificate),
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleBundle1.certificateRequest,
					)),
				},
				ExpectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-850937773"`},
			},
		},
		"do nothing if existing x509 certificate is up to date and valid for the cert and no other CertificateRequest exists": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IPSANAnnotationKey:      "",
								cmapi.AltNamesAnnotationKey:   "example.com",
								cmapi.CommonNameAnnotationKey: "example.com",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundle1.certBytes,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
			},
		},
		"update secret resource metadata if existing certificate is valid but missing annotations": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundle1.certBytes,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.certBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{"Normal UpdateMeta Updated metadata on Secret resource"},
			},
		},
		"update the Secret resource with the signed certificate if the CertificateRequest is ready": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       nil,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequestReady,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.certBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{"Normal Issued Certificate issued successfully"},
			},
		},
		"do nothing if the Secret resource is not in need of issuance even if a Ready CertificateRequest exists and contains different data": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      exampleBundle1.certificate.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IPSANAnnotationKey:      "",
								cmapi.AltNamesAnnotationKey:   "example.com",
								cmapi.CommonNameAnnotationKey: "example.com",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundle1.generateTestCertificate(exampleBundle1.certificate, nil),
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequestReady,
				},
			},
		},
		"issue new certificate if existing certificate data is garbage": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IPSANAnnotationKey:      "",
								cmapi.AltNamesAnnotationKey:   "example.com",
								cmapi.CommonNameAnnotationKey: "example.com",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       []byte("invalid"),
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequestReady,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.certBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{"Normal Issued Certificate issued successfully"},
			},
		},
		"delete existing certificate request if existing one contains a certificate nearing expiry": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IPSANAnnotationKey:      "",
								cmapi.AltNamesAnnotationKey:   "example.com",
								cmapi.CommonNameAnnotationKey: "example.com",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundle1.generateCertificateExpiring1H(exampleBundle1.certificate),
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					gen.CertificateRequestFrom(exampleBundle1.certificateRequestReady,
						gen.SetCertificateRequestCertificate(
							exampleBundle1.generateCertificateExpiring1H(exampleBundle1.certificate),
						),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleBundle1.certificateRequestReady.Name,
					)),
				},
			},
		},
		"delete existing certificate request if existing one contains a csr not valid for stored private key": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IPSANAnnotationKey:      "",
								cmapi.AltNamesAnnotationKey:   "example.com",
								cmapi.CommonNameAnnotationKey: "example.com",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundle1.generateCertificateExpiring1H(exampleBundle1.certificate),
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					gen.CertificateRequestFrom(exampleBundle1.certificateRequestReady,
						gen.SetCertificateRequestCSR(exampleECBundle.csrBytes),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleBundle1.certificateRequestReady.Name,
					)),
				},
				ExpectedEvents: []string{`Normal PrivateKeyLost Lost private key for CertificateRequest "test-850937773", deleting old resource`},
			},
		},
		"if a temporary certificate exists but the request has failed and contains no FailureTime, delete the request to cause a re-sync and retry": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequestFailed,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleBundle1.certificateRequestFailed.Name,
					)),
				},
				ExpectedEvents: []string{`Normal CertificateRequestRetry The failed CertificateRequest "test-850937773" will be retried now`},
			},
		},
		"if a temporary certificate exists but the request has failed and contains a FailureTime over an hour in the past, delete the request to cause a re-sync and retry": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					gen.CertificateRequestFrom(exampleBundle1.certificateRequestFailed,
						gen.SetCertificateRequestFailureTime(metav1.Time{
							Time: fixedClockStart.Add(-time.Minute * 61),
						})),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						gen.DefaultTestNamespace,
						exampleBundle1.certificateRequestFailed.Name,
					)),
				},
				ExpectedEvents: []string{`Normal CertificateRequestRetry The failed CertificateRequest "test-850937773" will be retried now`},
			},
		},
		"if a temporary certificate exists but the request has failed and contains a FailureTime less than an hour in the past, reschedule a re-sync in an hour": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					gen.CertificateRequestFrom(exampleBundle1.certificateRequestFailed,
						gen.SetCertificateRequestFailureTime(metav1.Time{
							Time: fixedClockStart.Add(-time.Minute * 59),
						})),
				},
				ExpectedActions: []testpkg.Action{},
				// We don't fire an event here as this could be called multiple times in quick succession
				ExpectedEvents: []string{},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock

			test.enableTempCerts = false
			runTest(t, test)
		})
	}
}

func TestTemporaryCertificateEnabled(t *testing.T) {
	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmapi.ObjectReference{Name: "test", Kind: "something", Group: "not-empty"}),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(time.Hour*36),
	)
	exampleBundle1 := mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
		gen.SetCertificateDNSNames("example.com"),
	))

	tests := map[string]testT{
		"issue a temporary certificate if no existing request exists and secret does not contain a cert": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       nil,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{`Normal TempCert Issued temporary certificate`},
			},
		},
		"issue a temporary certificate if existing request is pending and secret does not contain a cert": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       nil,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequest,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{`Normal TempCert Issued temporary certificate`},
			},
		},
		"issue a temporary certificate if existing request is Ready and secret does not contain a cert": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       nil,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequest,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{`Normal TempCert Issued temporary certificate`},
			},
		},
		"update the Secret resource with the signed certificate if the CertificateRequest is ready and contains temporary signed certificate": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IPSANAnnotationKey:      "",
								cmapi.AltNamesAnnotationKey:   "example.com",
								cmapi.CommonNameAnnotationKey: "example.com",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequestReady,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.certBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{`Normal Issued Certificate issued successfully`},
			},
		},
		"issue new certificate if existing certificate data is garbage, even if existing CertificateRequest is Ready": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IPSANAnnotationKey:      "",
								cmapi.AltNamesAnnotationKey:   "example.com",
								cmapi.CommonNameAnnotationKey: "example.com",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       []byte("invalid"),
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequestReady,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{`Normal TempCert Issued temporary certificate`},
			},
		},
		"generate a new temporary certificate if existing one is valid for different dnsNames": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.CertificateNameKey:      "test",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IPSANAnnotationKey:      "",
								cmapi.AltNamesAnnotationKey:   "example.com",
								cmapi.CommonNameAnnotationKey: "example.com",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey: exampleBundle1.generateCertificateTemporary(
								gen.CertificateFrom(exampleBundle1.certificate,
									gen.SetCertificateDNSNames("notexample.com"),
								),
							),
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{`Normal TempCert Issued temporary certificate`},
			},
		},
		"update the secret metadata if existing temporary certificate does not have annotations": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"custom-annotation":           "value",
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							cmapi.TLSCAKey:          nil,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"custom-annotation":           "value",
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
									cmapi.IPSANAnnotationKey:      "",
									cmapi.AltNamesAnnotationKey:   "example.com",
									cmapi.CommonNameAnnotationKey: "example.com",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
								corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{`Normal UpdateMeta Updated metadata on Secret resource`},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock

			test.enableTempCerts = true
			test.localTemporarySigner = testLocalTemporarySignerFn(exampleBundle1.localTemporaryCertificateBytes)
			runTest(t, test)
		})
	}
}

func TestUpdateStatus(t *testing.T) {
	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmapi.ObjectReference{Name: "test", Kind: "something", Group: "not-empty"}),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(time.Hour*36),
	)
	exampleBundle1 := mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
		gen.SetCertificateDNSNames("example.com"),
	))

	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	tests := map[string]testT{
		"mark status as NotFound if Secret does not exist for Certificate": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "NotFound",
								Message:            "Certificate does not exist",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"mark status as NotFound if Secret does not contain any data": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
						},
						Data: map[string][]byte{},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "NotFound",
								Message:            "Certificate does not exist",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"mark certificate as pending issuance if a secret exists with only a private key and no request exists": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "Pending",
								Message:            "Certificate pending issuance",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"mark certificate as in progress if existing Secret contains only private key and request exists & is up to date": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequest,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "InProgress",
								Message:            fmt.Sprintf("Waiting for CertificateRequest %q to complete", exampleBundle1.certificateRequest.Name),
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"mark certificate Ready if existing certificate is valid and up to date": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.certBytes,
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionTrue,
								Reason:             "Ready",
								Message:            "Certificate is up to date and has not expired",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateNotAfter(metav1.NewTime(exampleBundle1.cert.NotAfter)),
						),
					)),
				},
			},
		},
		"mark certificate Ready if existing certificate is expiring soon and a pending CertificateRequest exists": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.generateCertificateExpiring1H(exampleBundle1.certificate),
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequest,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionTrue,
								Reason:             "Ready",
								Message:            "Certificate is up to date and has not expired",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateNotAfter(metav1.NewTime(certificateNotAfter(exampleBundle1.generateCertificateExpiring1H(exampleBundle1.certificate)))),
						),
					)),
				},
			},
		},
		"mark certificate Expired if existing certificate is expired": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.generateCertificateExpired(exampleBundle1.certificate),
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "Expired",
								Message:            fmt.Sprintf("Certificate has expired on %s", certificateNotAfter(exampleBundle1.generateCertificateExpired(exampleBundle1.certificate)).Format(time.RFC822)),
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateNotAfter(metav1.NewTime(certificateNotAfter(exampleBundle1.generateCertificateExpired(exampleBundle1.certificate)))),
						),
					)),
				},
			},
		},
		"mark certificate InProgress if existing certificate is expired and CertificateRequest is in progress": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.generateCertificateExpired(exampleBundle1.certificate),
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequest,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "InProgress",
								Message:            fmt.Sprintf("Waiting for CertificateRequest %q to complete", exampleBundle1.certificateRequest.Name),
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateNotAfter(metav1.NewTime(certificateNotAfter(exampleBundle1.generateCertificateExpired(exampleBundle1.certificate)))),
						),
					)),
				},
			},
		},
		"mark certificate InProgress if existing certificate is expired and CertificateRequest is ready but not stored yet": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.generateCertificateExpired(exampleBundle1.certificate),
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequestReady,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "InProgress",
								Message:            fmt.Sprintf("Waiting for CertificateRequest %q to complete", exampleBundle1.certificateRequest.Name),
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateNotAfter(metav1.NewTime(certificateNotAfter(exampleBundle1.generateCertificateExpired(exampleBundle1.certificate)))),
						),
					)),
				},
			},
		},
		"mark certificate DoesNotMatch if existing Certificate does not match spec and no request is in progress": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey: exampleBundle1.generateTestCertificate(
								gen.CertificateFrom(exampleBundle1.certificate,
									gen.SetCertificateDNSNames("notexample.com"),
								), nil,
							),
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "DoesNotMatch",
								Message:            "Common name on TLS certificate not up to date: \"notexample.com\", DNS names on TLS certificate not up to date: [\"notexample.com\"]",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"mark certificate InProgress if existing Certificate does not match spec and a request is in progress": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey: exampleBundle1.generateTestCertificate(
								gen.CertificateFrom(exampleBundle1.certificate,
									gen.SetCertificateDNSNames("notexample.com"),
								), nil,
							),
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequest,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "InProgress",
								Message:            fmt.Sprintf("Waiting for CertificateRequest %q to complete", exampleBundle1.certificateRequest.Name),
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"mark certificate TemporaryCertificate if secret contains a valid temporary certificate and no request exists": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "TemporaryCertificate",
								Message:            "Certificate issuance in progress. Temporary certificate issued.",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"mark certificate InProgress if secret contains a valid temporary certificate and a request exists": {
			certificate: exampleBundle1.certificate,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle1.certificate.Spec.SecretName,
							Namespace: exampleBundle1.certificate.Namespace,
							Annotations: map[string]string{
								cmapi.IssuerNameAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Name,
								cmapi.IssuerKindAnnotationKey: exampleBundle1.certificate.Spec.IssuerRef.Kind,
							},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle1.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle1.localTemporaryCertificateBytes,
						},
					},
				},
				CertManagerObjects: []runtime.Object{
					exampleBundle1.certificate,
					exampleBundle1.certificateRequest,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleBundle1.certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "InProgress",
								Message:            fmt.Sprintf("Waiting for CertificateRequest %q to complete", exampleBundle1.certificateRequest.Name),
								LastTransitionTime: &metaFixedClockStart,
							}),
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
			test.builder.T = t
			test.builder.Init()
			defer test.builder.Stop()

			testManager := &certificateRequestManager{}
			testManager.Register(test.builder.Context)
			testManager.clock = fixedClock
			test.builder.Start()

			err := testManager.updateCertificateStatus(context.Background(), test.certificate, test.certificate.DeepCopy())
			if err != nil && !test.expectedErr {
				t.Errorf("expected to not get an error, but got: %v", err)
			}
			if err == nil && test.expectedErr {
				t.Errorf("expected to get an error but did not get one")
			}
			test.builder.CheckAndFinish(err)
		})
	}
}

type testT struct {
	builder                 *testpkg.Builder
	generatePrivateKeyBytes generatePrivateKeyBytesFn
	generateCSR             generateCSRFn
	localTemporarySigner    localTemporarySignerFn
	enableTempCerts         bool
	certificate             *cmapi.Certificate
	expectedErr             bool
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	testManager := &certificateRequestManager{issueTemporaryCerts: test.enableTempCerts}
	testManager.Register(test.builder.Context)
	testManager.generatePrivateKeyBytes = test.generatePrivateKeyBytes
	testManager.generateCSR = test.generateCSR
	testManager.localTemporarySigner = test.localTemporarySigner
	testManager.issueTemporaryCerts = test.enableTempCerts
	test.builder.Start()

	err := testManager.processCertificate(context.Background(), test.certificate)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}
