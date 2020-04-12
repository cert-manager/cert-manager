/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package issuing

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestSecretsManager(t *testing.T) {
	type testT struct {
		builder *testpkg.Builder

		certificateOptions controllerpkg.CertificateOptions
		certificate        *cmapi.Certificate
		secretData         secretData

		expectedErr bool
	}

	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "ca-issuer", Kind: "Issuer", Group: "not-empty"}),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(time.Hour*36),
		gen.SetCertificateDNSNames("example.com"),
	)
	exampleBundle := mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
		gen.SetCertificateDNSNames("example.com"),
	))

	tests := map[string]testT{
		"if secret does not exists and unable to decode certificate, then error": {
			certificate: exampleBundle.certificate,
			secretData:  secretData{cert: []byte("test-cert"), ca: []byte("test-ca"), sk: []byte("test-key")},
			builder: &testpkg.Builder{
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: true,
		},

		"if secret does not exist, create new Secret, with owner enabled": {
			certificate: exampleBundle.certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: true,
			},
			secretData: secretData{cert: exampleBundle.certBytes, ca: []byte("test-ca"), sk: []byte("test-key")},
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
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle.certificate.Spec.IssuerRef.Name,

									cmapi.CommonNameAnnotationKey: exampleBundle.cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(exampleBundle.cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(exampleBundle.cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(exampleBundle.cert.URIs), ","),
								},
								OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(exampleBundle.certificate, certificateGvk)},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.certBytes,
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
			certificate: exampleBundle.certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: true,
			},
			secretData: secretData{cert: exampleBundle.certBytes, ca: []byte("test-ca"), sk: []byte("test-key")},
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

									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle.certificate.Spec.IssuerRef.Name,

									cmapi.CommonNameAnnotationKey: exampleBundle.cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(exampleBundle.cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(exampleBundle.cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(exampleBundle.cert.URIs), ","),
								},
								OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(exampleBundle.certificate, certificateGvk)},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.certBytes,
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
			certificate: exampleBundle.certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: false,
			},
			secretData: secretData{cert: exampleBundle.certBytes, ca: []byte("test-ca"), sk: []byte("test-key")},
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
									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle.certificate.Spec.IssuerRef.Name,

									cmapi.CommonNameAnnotationKey: exampleBundle.cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(exampleBundle.cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(exampleBundle.cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(exampleBundle.cert.URIs), ","),
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.certBytes,
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
			certificate: exampleBundle.certificate,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: false,
			},
			secretData: secretData{cert: exampleBundle.certBytes, ca: []byte("test-ca"), sk: []byte("test-key")},
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

									cmapi.CertificateNameKey:      "test",
									cmapi.IssuerKindAnnotationKey: exampleBundle.certificate.Spec.IssuerRef.Kind,
									cmapi.IssuerNameAnnotationKey: exampleBundle.certificate.Spec.IssuerRef.Name,

									cmapi.CommonNameAnnotationKey: exampleBundle.cert.Subject.CommonName,
									cmapi.AltNamesAnnotationKey:   strings.Join(exampleBundle.cert.DNSNames, ","),
									cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(exampleBundle.cert.IPAddresses), ","),
									cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(exampleBundle.cert.URIs), ","),
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.certBytes,
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

			testManager := newSecretsManager(
				kubeClient,
				secretsLister,
				test.certificateOptions,
			)

			test.builder.Start()

			err := testManager.updateData(context.Background(), test.certificate, test.secretData)
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
