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
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/internal/controller/feature"
	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	internaltest "github.com/jetstack/cert-manager/pkg/controller/certificates/internal/test"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
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
	// enable feature gate additional private key for this test
	defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultMutableFeatureGate, feature.AdditionalCertificateOutputFormats, true)()
	baseCertWithAdditionalOutputFormatDER := gen.CertificateFrom(baseCertBundle.Certificate,
		gen.SetCertificateAdditionalOutputFormats(cmapi.CertificateAdditionalOutputFormat{Type: "DER"}),
	)
	baseCertWithAdditionalOutputFormatCombinedPEM := gen.CertificateFrom(baseCertBundle.Certificate,
		gen.SetCertificateAdditionalOutputFormats(cmapi.CertificateAdditionalOutputFormat{Type: "CombinedPEM"}),
	)
	baseCertWithAdditionalOutputFormats := gen.CertificateFrom(baseCertBundle.Certificate,
		gen.SetCertificateAdditionalOutputFormats(
			cmapi.CertificateAdditionalOutputFormat{Type: "DER"},
			cmapi.CertificateAdditionalOutputFormat{Type: "CombinedPEM"},
		),
	)
	block, _ := pem.Decode(baseCertBundle.PrivateKeyBytes)
	tlsDerContent := block.Bytes

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
							Labels: map[string]string{},
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

		"if secret does not exist, create new Secret with additional output format DER": {
			certificate: baseCertWithAdditionalOutputFormatDER,
			SecretData:  SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes},
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
								corev1.TLSCertKey:                   baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey:             baseCertBundle.PrivateKeyBytes,
								cmmeta.TLSCAKey:                     []byte("test-ca"),
								cmapi.CertificateOutputFormatDERKey: tlsDerContent,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},

		"if secret does not exist, create new Secret with additional output format CombinedPEM": {
			certificate: baseCertWithAdditionalOutputFormatCombinedPEM,
			SecretData:  SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes},
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
								corev1.TLSCertKey:                           baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey:                     baseCertBundle.PrivateKeyBytes,
								cmmeta.TLSCAKey:                             []byte("test-ca"),
								cmapi.CertificateOutputFormatCombinedPEMKey: []byte(strings.Join([]string{string(baseCertBundle.PrivateKeyBytes), string(baseCertBundle.CertBytes)}, "\n")),
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},

		"if secret does not exist, create new Secret with additional output format DER and CombinedPEM": {
			certificate: baseCertWithAdditionalOutputFormats,
			SecretData:  SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes},
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
								corev1.TLSCertKey:                           baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey:                     baseCertBundle.PrivateKeyBytes,
								cmmeta.TLSCAKey:                             []byte("test-ca"),
								cmapi.CertificateOutputFormatDERKey:         tlsDerContent,
								cmapi.CertificateOutputFormatCombinedPEMKey: []byte(strings.Join([]string{string(baseCertBundle.PrivateKeyBytes), string(baseCertBundle.CertBytes)}, "\n")),
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},

		"if secret exists, with tls-combined.pem and key.der but no additional formats specified": {
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
							corev1.TLSCertKey:                           []byte("foo"),
							corev1.TLSPrivateKeyKey:                     []byte("foo"),
							cmmeta.TLSCAKey:                             []byte("foo"),
							cmapi.CertificateOutputFormatDERKey:         []byte("foo"),
							cmapi.CertificateOutputFormatCombinedPEMKey: []byte("foo"),
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

		"if secret exists, with tls-combined.pem and key.der but only DER Format specified": {
			certificate: baseCertWithAdditionalOutputFormatDER,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: false,
			},
			SecretData: SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes},
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
							corev1.TLSCertKey:                           []byte("foo"),
							corev1.TLSPrivateKeyKey:                     []byte("foo"),
							cmmeta.TLSCAKey:                             []byte("foo"),
							cmapi.CertificateOutputFormatDERKey:         []byte("foo"),
							cmapi.CertificateOutputFormatCombinedPEMKey: []byte("foo"),
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
								corev1.TLSCertKey:                   baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey:             baseCertBundle.PrivateKeyBytes,
								cmmeta.TLSCAKey:                     []byte("test-ca"),
								cmapi.CertificateOutputFormatDERKey: tlsDerContent,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
			expectedErr: false,
		},

		"if secret exists, with tls-combined.pem and key.der but only Combined PEM Format specified": {
			certificate: baseCertWithAdditionalOutputFormatCombinedPEM,
			certificateOptions: controllerpkg.CertificateOptions{
				EnableOwnerRef: false,
			},
			SecretData: SecretData{Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes},
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
							corev1.TLSCertKey:                           []byte("foo"),
							corev1.TLSPrivateKeyKey:                     []byte("foo"),
							cmmeta.TLSCAKey:                             []byte("foo"),
							cmapi.CertificateOutputFormatDERKey:         []byte("foo"),
							cmapi.CertificateOutputFormatCombinedPEMKey: []byte("foo"),
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
								corev1.TLSCertKey:                           baseCertBundle.CertBytes,
								corev1.TLSPrivateKeyKey:                     baseCertBundle.PrivateKeyBytes,
								cmmeta.TLSCAKey:                             []byte("test-ca"),
								cmapi.CertificateOutputFormatCombinedPEMKey: []byte(strings.Join([]string{string(baseCertBundle.PrivateKeyBytes), string(baseCertBundle.CertBytes)}, "\n")),
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
				test.builder.RESTConfig,
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

func Test_getCertificateSecret(t *testing.T) {
	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-certificate"},
		Spec:       cmapi.CertificateSpec{SecretName: "test-secret"},
	}

	tests := map[string]struct {
		secretApplyFeatureEnabled    bool
		secretOwnerRefernecesEnabled bool
		existingSecret               *corev1.Secret

		expSecret       *corev1.Secret
		expSecretExists bool
	}{
		"if secret doesn't exist, applyFeature=false ownerRefFeature=false, expect empty secret with no owner ref": {
			secretApplyFeatureEnabled: false, secretOwnerRefernecesEnabled: false, existingSecret: nil,
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data:       make(map[string][]byte), Type: corev1.SecretTypeTLS,
			},
			expSecretExists: false,
		},
		"if secret doesn't exist, applyFeature=true ownerRefFeature=false, expect empty secret with no owner ref": {
			secretApplyFeatureEnabled: true, secretOwnerRefernecesEnabled: false, existingSecret: nil,
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data:       make(map[string][]byte), Type: corev1.SecretTypeTLS,
			},
			expSecretExists: false,
		},
		"if secret doesn't exist, applyFeature=false ownerRefFeature=true, expect empty secret with owner ref": {
			secretApplyFeatureEnabled: false, secretOwnerRefernecesEnabled: true, existingSecret: nil,
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)}},
				Data:       make(map[string][]byte), Type: corev1.SecretTypeTLS,
			},
			expSecretExists: false,
		},
		"if secret doesn't exist, applyFeature=true ownerRefFeature=true, expect empty secret with owner ref": {
			secretApplyFeatureEnabled: true, secretOwnerRefernecesEnabled: true, existingSecret: nil,
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)}},
				Data:       make(map[string][]byte), Type: corev1.SecretTypeTLS,
			},
			expSecretExists: false,
		},
		"if secret exists, applyFeature=false ownerRefFeature=false, expect the exact same Secret to be returned": {
			secretApplyFeatureEnabled: false, secretOwnerRefernecesEnabled: false,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{"abc": []byte("123"), "hello-world": []byte("bar"), "tls.crt": []byte("cert"), "tls.key": []byte("key")}, Type: corev1.SecretTypeTLS,
			},
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{"abc": []byte("123"), "hello-world": []byte("bar"), "tls.crt": []byte("cert"), "tls.key": []byte("key")}, Type: corev1.SecretTypeTLS,
			},
			expSecretExists: true,
		},
		"if secret exists, applyFeature=false ownerRefFeature=true, expect the exact same Secret to be returned but with OwnerReferences set": {
			secretApplyFeatureEnabled: false, secretOwnerRefernecesEnabled: true,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{"abc": []byte("123"), "hello-world": []byte("bar"), "tls.crt": []byte("cert"), "tls.key": []byte("key")}, Type: corev1.SecretType("test"),
			},
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{"abc": []byte("123"), "hello-world": []byte("bar"), "tls.crt": []byte("cert"), "tls.key": []byte("key")}, Type: corev1.SecretType("test"),
			},
			expSecretExists: true,
		},
		"if secret exists, applyFeature=true ownerRefFeature=false, expect the secret to be returned but only with the cert-manager managed data keys to be set": {
			secretApplyFeatureEnabled: true, secretOwnerRefernecesEnabled: false,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{"abc": []byte("123"), "hello-world": []byte("bar"), "tls.crt": []byte("cert"), "tls.key": []byte("key"), "ca.crt": []byte("ca")}, Type: corev1.SecretTypeOpaque,
			},
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
				},
				Data: map[string][]byte{"tls.crt": []byte("cert"), "tls.key": []byte("key"), "ca.crt": []byte("ca")}, Type: corev1.SecretTypeOpaque,
			},
			expSecretExists: true,
		},
		"if secret exists, applyFeature=true ownerRefFeature=true, expect the secret to be returned but only with the cert-manager managed data keys to be set, and owner references": {
			secretApplyFeatureEnabled: true, secretOwnerRefernecesEnabled: true,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{"abc": []byte("123"), "hello-world": []byte("bar"), "tls.crt": []byte("cert"), "tls.key": []byte("key"), "ca.crt": []byte("ca")}, Type: corev1.SecretTypeTLS,
			},
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
				},
				Data: map[string][]byte{"tls.crt": []byte("cert"), "tls.key": []byte("key"), "ca.crt": []byte("ca")}, Type: corev1.SecretTypeTLS,
			},
			expSecretExists: true,
		},
		"if secret exists, applyFeature=true ownerRefFeature=true, expect the secret to be returned but only with the cert-manager managed data keys to be set, and owner references, with original Type set": {
			secretApplyFeatureEnabled: true, secretOwnerRefernecesEnabled: true,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{"abc": []byte("123"), "hello-world": []byte("bar"), "tls.crt": []byte("cert"), "tls.key": []byte("key"), "ca.crt": []byte("ca")}, Type: corev1.SecretTypeOpaque,
			},
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
				},
				Data: map[string][]byte{"tls.crt": []byte("cert"), "tls.key": []byte("key"), "ca.crt": []byte("ca")}, Type: corev1.SecretTypeOpaque,
			},
			expSecretExists: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.secretApplyFeatureEnabled {
				assert.NoError(t,
					utilfeature.DefaultMutableFeatureGate.Set("ExperimentalSecretApplySecretTemplateControllerMinKubernetesVTODO=true"),
				)
			}
			t.Cleanup(func() {
				assert.NoError(t,
					utilfeature.DefaultMutableFeatureGate.Set("ExperimentalSecretApplySecretTemplateControllerMinKubernetesVTODO=false"),
				)
			})

			// Create and initialise a new unit test builder.
			builder := &testpkg.Builder{
				T: t,
			}
			if test.existingSecret != nil {
				// Ensures secret is loaded into the builder's fake clientset.
				builder.KubeObjects = append(builder.KubeObjects, test.existingSecret)
			}

			builder.Init()

			s := SecretsManager{
				kubeClient:                  builder.Client,
				secretLister:                builder.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
				restConfig:                  builder.RESTConfig,
				enableSecretOwnerReferences: test.secretOwnerRefernecesEnabled,
			}

			builder.Start()
			defer builder.Stop()

			gotSecret, gotSecretExists, err := s.getCertificateSecret(context.Background(), crt)
			assert.NoError(t, err)

			assert.Equal(t, test.expSecretExists, gotSecretExists, "unexpected secret existed")
			assert.Equal(t, test.expSecret, gotSecret, "unexpected returned secret")
		})
	}
}

func Test_secretWithMaybeOwnerRef(t *testing.T) {
	tests := map[string]struct {
		secretOwnerRefernecesEnabled bool
		expOwnerReferneces           bool
	}{
		"if secret ownership disabled, expect no owner reference": {
			secretOwnerRefernecesEnabled: false,
			expOwnerReferneces:           false,
		},
		"if secret ownership enabled, expect owner reference": {
			secretOwnerRefernecesEnabled: true,
			expOwnerReferneces:           true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			secret := (&SecretsManager{enableSecretOwnerReferences: test.secretOwnerRefernecesEnabled}).secretWithMaybeOwnerRef(
				&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-certificate"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"}},
			)

			assert.Equal(t, len(secret.OwnerReferences) > 0, test.expOwnerReferneces, "unexpected owner reference on Secret")
		})
	}
}
