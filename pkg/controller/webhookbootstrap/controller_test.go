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

package webhookbootstrap

import (
	"context"
	"crypto"
	"crypto/x509"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
)

const (
	defaultWebhookNamespace   = "testns"
	defaultWebhookCAName      = "ca-secret"
	defaultWebhookServingName = "serving-secret"
)

var (
	defaultWebhookDNSNames = []string{"testdomain.com"}
)

type testT struct {
	builder                 *testpkg.Builder
	generatePrivateKeyBytes generatePrivateKeyBytesFn
	signCertificate         signCertificateFunc
	key                     string
	expectedErr             bool
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	c := &controller{}
	test.builder.Init()
	defer test.builder.Stop()

	test.builder.Context.WebhookBootstrapOptions.Namespace = defaultWebhookNamespace
	test.builder.Context.WebhookBootstrapOptions.DNSNames = defaultWebhookDNSNames
	test.builder.Context.WebhookBootstrapOptions.ServingSecretName = defaultWebhookServingName
	test.builder.Context.WebhookBootstrapOptions.CASecretName = defaultWebhookCAName
	_, waitSync, runFn, err := c.Register(test.builder.Context)
	if err != nil {
		t.Errorf("failed to setup controller: %v", err)
		t.FailNow()
	}
	test.builder.RegisterAdditionalSyncFuncs(waitSync...)
	test.builder.Start(runFn...)

	if test.generatePrivateKeyBytes != nil {
		c.generatePrivateKeyBytes = test.generatePrivateKeyBytes
	}
	if test.signCertificate != nil {
		c.signCertificate = test.signCertificate
	}

	test.builder.Sync()

	err = c.ProcessItem(context.Background(), test.key)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}

func TestProcessItem(t *testing.T) {
	exampleBundle := mustCreateCryptoBundle(t, gen.Certificate(defaultWebhookCAName,
		gen.SetCertificateDNSNames(defaultWebhookDNSNames...),
		gen.SetCertificateOrganization("cert-manager.system"),
	))
	exampleBadDNSNameBundle := mustCreateCryptoBundle(t, gen.Certificate(defaultWebhookCAName,
		gen.SetCertificateDNSNames("nottherightdomain.com"),
		gen.SetCertificateOrganization("cert-manager.system"),
	))
	exampleBundleCA := mustCreateCryptoBundle(t, gen.Certificate(defaultWebhookCAName,
		gen.SetCertificateCommonName("cert-manager.webhook.ca"),
		gen.SetCertificateIsCA(true),
		gen.SetCertificateOrganization("cert-manager.system"),
	))

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultWebhookCAName,
			Namespace: defaultWebhookNamespace,
		},
		Type: corev1.SecretTypeTLS,
	}
	caSecretKey := caSecret.Namespace + "/" + caSecret.Name

	servingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultWebhookServingName,
			Namespace: defaultWebhookNamespace,
		},
		Type: corev1.SecretTypeTLS,
	}
	servingSecretKey := servingSecret.Namespace + "/" + servingSecret.Name

	tests := map[string]testT{
		"do nothing if the secret's namespace does not match the webhook namespace": {
			key: "notmyns/" + defaultWebhookCAName,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookCAName,
							Namespace: "notmyns",
						},
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
		},
		"generate a new private key for the CA secret if none exists": {
			key:                     caSecretKey,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle.privateKeyBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					caSecret,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						caSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: caSecret.Namespace,
								Name:      caSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       nil,
								corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"generate a new private key for the CA secret if existing private key is garbage": {
			key:                     caSecretKey,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle.privateKeyBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookCAName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: []byte("garbage"),
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						caSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: caSecret.Namespace,
								Name:      caSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       nil,
								corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"return an error for the serving secret if the ca secret is empty": {
			key:                     servingSecretKey,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle.privateKeyBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					caSecret,
					servingSecret,
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: true,
		},
		"return an error for the serving secret if the ca certificate data is empty": {
			key:                     servingSecretKey,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle.privateKeyBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookCAName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
					servingSecret,
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: true,
		},
		"generate a new private key for the serving secret if none exists": {
			key:                     servingSecretKey,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle.privateKeyBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookCAName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
					servingSecret,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						servingSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: servingSecret.Namespace,
								Name:      servingSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       nil,
								corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"generate a new private key for the serving secret if existing private key is garbage": {
			key:                     servingSecretKey,
			generatePrivateKeyBytes: testGeneratePrivateKeyBytesFn(exampleBundle.privateKeyBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookCAName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookServingName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: []byte("garbage"),
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						servingSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: servingSecret.Namespace,
								Name:      servingSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       nil,
								corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
								cmapi.TLSCAKey:          nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"sign a new CA certificate if none currently exists": {
			key:             caSecretKey,
			signCertificate: testSignCertificateFn(exampleBundleCA.certBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookCAName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						caSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: caSecret.Namespace,
								Name:      caSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundleCA.certBytes,
								corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
								cmapi.TLSCAKey:          exampleBundleCA.certBytes,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"sign a new CA certificate if existing one is garbage": {
			key:             caSecretKey,
			signCertificate: testSignCertificateFn(exampleBundleCA.certBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookCAName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
							corev1.TLSCertKey:       []byte("garbage"),
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						caSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: caSecret.Namespace,
								Name:      caSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundleCA.certBytes,
								corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
								cmapi.TLSCAKey:          exampleBundleCA.certBytes,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"sign a new serving certificate if none currently exists": {
			key:             servingSecretKey,
			signCertificate: testSignCertificateFn(exampleBundle.certBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: caSecret.Namespace,
							Name:      caSecret.Name,
							Annotations: map[string]string{
								cmapi.AllowsInjectionFromSecretAnnotation: "true",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundleCA.certBytes,
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
							cmapi.TLSCAKey:          exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookServingName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						servingSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: servingSecret.Namespace,
								Name:      servingSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.certBytes,
								corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
								cmapi.TLSCAKey:          exampleBundleCA.certBytes,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"sign a new serving certificate if existing one is garbage": {
			key:             servingSecretKey,
			signCertificate: testSignCertificateFn(exampleBundle.certBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: caSecret.Namespace,
							Name:      caSecret.Name,
							Annotations: map[string]string{
								cmapi.AllowsInjectionFromSecretAnnotation: "true",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundleCA.certBytes,
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
							cmapi.TLSCAKey:          exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookServingName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						servingSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: servingSecret.Namespace,
								Name:      servingSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.certBytes,
								corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
								cmapi.TLSCAKey:          exampleBundleCA.certBytes,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"sign a new serving certificate if existing one contains mismatching private/cert pair": {
			key:             servingSecretKey,
			signCertificate: testSignCertificateFn(exampleBundle.certBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: caSecret.Namespace,
							Name:      caSecret.Name,
							Annotations: map[string]string{
								cmapi.AllowsInjectionFromSecretAnnotation: "true",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundleCA.certBytes,
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
							cmapi.TLSCAKey:          exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookServingName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundleCA.certBytes,
							corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
							cmapi.TLSCAKey:          exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						servingSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: servingSecret.Namespace,
								Name:      servingSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.certBytes,
								corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
								cmapi.TLSCAKey:          exampleBundleCA.certBytes,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"sign a new serving certificate if existing one contains wrong dnsNames": {
			key:             servingSecretKey,
			signCertificate: testSignCertificateFn(exampleBundle.certBytes),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: caSecret.Namespace,
							Name:      caSecret.Name,
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundleCA.certBytes,
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
							cmapi.TLSCAKey:          exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookServingName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBadDNSNameBundle.certBytes,
							corev1.TLSPrivateKeyKey: exampleBadDNSNameBundle.privateKeyBytes,
							cmapi.TLSCAKey:          exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						servingSecret.Namespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: servingSecret.Namespace,
								Name:      servingSecret.Name,
								Annotations: map[string]string{
									cmapi.AllowsInjectionFromSecretAnnotation: "true",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       exampleBundle.certBytes,
								corev1.TLSPrivateKeyKey: exampleBadDNSNameBundle.privateKeyBytes,
								cmapi.TLSCAKey:          exampleBundleCA.certBytes,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
				ExpectedEvents: []string{},
			},
		},
		"do nothing if the existing CA secret is up to date": {
			key: caSecretKey,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookCAName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
		},
		"do nothing if the existing serving secret is up to date": {
			key: servingSecretKey,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookCAName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundleCA.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundleCA.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      defaultWebhookServingName,
							Namespace: defaultWebhookNamespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.privateKeyBytes,
							corev1.TLSCertKey:       exampleBundle.certBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

type cryptoBundle struct {
	// certificate is the Certificate resource used to create this bundle
	certificate *cmapi.Certificate

	// privateKey is the private key used as the complement to the certificates
	// in this bundle
	privateKey      crypto.Signer
	privateKeyBytes []byte

	// cert is a signed certificate
	cert      *x509.Certificate
	certBytes []byte
}

func mustCreateCryptoBundle(t *testing.T, crt *cmapi.Certificate) cryptoBundle {
	c, err := createCryptoBundle(crt)
	if err != nil {
		t.Fatalf("error generating crypto bundle: %v", err)
	}
	return *c
}

func createCryptoBundle(crt *cmapi.Certificate) (*cryptoBundle, error) {
	privateKey, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := pki.EncodePrivateKey(privateKey, crt.Spec.KeyEncoding)
	if err != nil {
		return nil, err
	}

	unsignedCert, err := pki.GenerateTemplate(crt)
	if err != nil {
		return nil, err
	}

	certBytes, cert, err := pki.SignCertificate(unsignedCert, unsignedCert, privateKey.Public(), privateKey)
	if err != nil {
		return nil, err
	}

	return &cryptoBundle{
		certificate:     crt,
		privateKey:      privateKey,
		privateKeyBytes: privateKeyBytes,
		cert:            cert,
		certBytes:       certBytes,
	}, nil
}

func testGeneratePrivateKeyBytesFn(b []byte) generatePrivateKeyBytesFn {
	return func(*cmapi.Certificate) ([]byte, error) {
		return b, nil
	}
}

func testSignCertificateFn(b []byte) signCertificateFunc {
	return func(_ *cmapi.Certificate, _, _ crypto.Signer, _ *x509.Certificate) ([]byte, error) {
		return b, nil
	}
}
