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

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	internaltest "github.com/cert-manager/cert-manager/pkg/controller/certificates/internal/test"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
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
	exampleBundle := internaltest.MustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
		gen.SetCertificateDNSNames("example.com"),
	), fixedClock)

	tests := map[string]testT{
		"if secret does not exists and unable to decode certificate, then error": {
			certificate: exampleBundle.Certificate,
			SecretData:  SecretData{Certificate: []byte("test-cert"), CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
			builder: &testpkg.Builder{
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: true,
		},

		"if secret does not exist, create new Secret, with owner enabled": {
			certificate: exampleBundle.Certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: true,
			},
			SecretData: SecretData{Certificate: exampleBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
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

									cmapi.CommonNameAnnotationKey: exampleBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(exampleBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(exampleBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(exampleBundle.Cert.URIs), ","),
								},
								OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(exampleBundle.Certificate, certificateGvk)},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.CertBytes,
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
			certificate: exampleBundle.Certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: true,
			},
			SecretData: SecretData{Certificate: exampleBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
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

									cmapi.CommonNameAnnotationKey: exampleBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(exampleBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(exampleBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(exampleBundle.Cert.URIs), ","),
								},
								OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(exampleBundle.Certificate, certificateGvk)},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.CertBytes,
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
			certificate: exampleBundle.Certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: false,
			},
			SecretData: SecretData{Certificate: exampleBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
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

									cmapi.CommonNameAnnotationKey: exampleBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(exampleBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(exampleBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(exampleBundle.Cert.URIs), ","),
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.CertBytes,
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
			certificate: exampleBundle.Certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: false,
			},
			SecretData: SecretData{Certificate: exampleBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key")},
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

									cmapi.CommonNameAnnotationKey: exampleBundle.Cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(exampleBundle.Cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(exampleBundle.Cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(exampleBundle.Cert.URIs), ","),
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.CertBytes,
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
