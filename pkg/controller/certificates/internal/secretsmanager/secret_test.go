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

package secretsmanager

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	internaltest "github.com/jetstack/cert-manager/pkg/controller/certificates/internal/test"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func TestSecretsManager(t *testing.T) {
	type testT struct {
		builder *testpkg.Builder

		certificateOptions controllerpkg.CertificateOptions
		certificate        *cmapi.Certificate
		SecretData         SecretData

		expectedErr bool
	}

	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "ca-issuer", Kind: "Issuer", Group: "foo.io"}),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(time.Hour*36),
		gen.SetCertificateDNSNames("example.com"),
	)
	baseCertBundle := internaltest.MustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
		gen.SetCertificateDNSNames("example.com"),
	), fixedClock)

	baseCertWithSecretTemplate := gen.CertificateFrom(baseCertBundle.Certificate,
		gen.SetCertificateSecretTemplate(map[string]string{
			"template":  "annotation",
			"my-custom": "annotation-from-secret",
		}, map[string]string{
			"template": "label",
		}),
	)

	tests := map[string]testT{
		"if secret does not exists and unable to decode certificate, then error": {
			certificate: baseCertBundle.Certificate,
			SecretData:  SecretData{Certificate: []byte("test-cert"), CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
			builder: &testpkg.Builder{
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: true,
		},

		"if secret does not exist, create new Secret, with owner enabled": {
			certificate: baseCertBundle.Certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: true,
			},
			SecretData: SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									cmapi.CertificateNameKey:       "test",
									cmapi.IssuerGroupAnnotationKey: "foo.io",
									cmapi.IssuerKindAnnotationKey:  "Issuer",
									cmapi.IssuerNameAnnotationKey:  "ca-issuer",

									cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
								},
								Labels:          map[string]string{},
								OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(baseCertBundle.Certificate, certificateGvk)},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey: []byte("test-key"),
								cmmeta.TLSCAKey:         []byte("test-ca"),
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},

		"if secret does exist, update existing Secret and leave custom annotations, with owner enabled": {
			certificate: baseCertBundle.Certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: true,
			},
			SecretData: SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       []byte("foo"),
							corev1.TLSPrivateKeyKey: []byte("foo"),
							cmmeta.TLSCAKey:         []byte("foo"),
						},
						Type: corev1.SecretTypeTLS,
					},
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
									"my-custom": "annotation",

									cmapi.CertificateNameKey:       "test",
									cmapi.IssuerGroupAnnotationKey: "foo.io",
									cmapi.IssuerKindAnnotationKey:  "Issuer",
									cmapi.IssuerNameAnnotationKey:  "ca-issuer",

									cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
								},
								Labels:          map[string]string{},
								OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(baseCertBundle.Certificate, certificateGvk)},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey: []byte("test-key"),
								cmmeta.TLSCAKey:         []byte("test-ca"),
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},

		"if secret does exist, update existing Secret and add annotations set in secretTemplate": {
			certificate: baseCertWithSecretTemplate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: true,
			},
			SecretData: SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       []byte("foo"),
							corev1.TLSPrivateKeyKey: []byte("foo"),
							cmmeta.TLSCAKey:         []byte("foo"),
						},
						Type: corev1.SecretTypeTLS,
					},
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
									"my-custom": "annotation-from-secret",
									"template":  "annotation",

									cmapi.CertificateNameKey:       "test",
									cmapi.IssuerGroupAnnotationKey: "foo.io",
									cmapi.IssuerKindAnnotationKey:  "Issuer",
									cmapi.IssuerNameAnnotationKey:  "ca-issuer",

									cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
								},
								Labels: map[string]string{
									"template": "label",
								},
								OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(baseCertBundle.Certificate, certificateGvk)},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey: []byte("test-key"),
								cmmeta.TLSCAKey:         []byte("test-ca"),
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},

		"if secret does not exist, create new Secret, with owner disabled": {
			certificate: baseCertBundle.Certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: false,
			},
			SecretData: SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									cmapi.CertificateNameKey:       "test",
									cmapi.IssuerGroupAnnotationKey: "foo.io",
									cmapi.IssuerKindAnnotationKey:  "Issuer",
									cmapi.IssuerNameAnnotationKey:  "ca-issuer",

									cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
								},
								Labels: map[string]string{},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey: []byte("test-key"),
								cmmeta.TLSCAKey:         []byte("test-ca"),
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},

		"if secret does not exist, create new Secret using the secret template": {
			certificate: baseCertWithSecretTemplate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: false,
			},
			SecretData: SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Annotations: map[string]string{
									"template":  "annotation",
									"my-custom": "annotation-from-secret",

									cmapi.CertificateNameKey:       "test",
									cmapi.IssuerGroupAnnotationKey: "foo.io",
									cmapi.IssuerKindAnnotationKey:  "Issuer",
									cmapi.IssuerNameAnnotationKey:  "ca-issuer",

									cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
								},
								Labels: map[string]string{
									"template": "label",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey: []byte("test-key"),
								cmmeta.TLSCAKey:         []byte("test-ca"),
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},

		"if secret does exist, update existing Secret and leave custom annotations, with owner disabled.": {
			certificate: baseCertBundle.Certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: false,
			},
			SecretData: SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       []byte("foo"),
							corev1.TLSPrivateKeyKey: []byte("foo"),
							cmmeta.TLSCAKey:         []byte("foo"),
						},
						Type: corev1.SecretTypeTLS,
					},
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
									"my-custom": "annotation",

									cmapi.CertificateNameKey:       "test",
									cmapi.IssuerGroupAnnotationKey: "foo.io",
									cmapi.IssuerKindAnnotationKey:  "Issuer",
									cmapi.IssuerNameAnnotationKey:  "ca-issuer",

									cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
								},
								Labels: map[string]string{},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey: []byte("test-key"),
								cmmeta.TLSCAKey:         []byte("test-ca"),
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},
	}

	// TODO: add to these tests once the JKS/PKCS12 support is updated

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock
			test.builder.T = t
			test.builder.Init()
			defer test.builder.Stop()

			kubeClient := test.builder.Client
			secretsLister := test.builder.KubeSharedInformerFactory.Core().V1().Secrets().Lister()

			testManager := New(
				kubeClient,
				secretsLister,
				test.certificateOptions.EnableOwnerRef,
			)

			test.builder.Start()

			err := testManager.UpdateData(context.Background(), test.certificate, test.SecretData)
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
