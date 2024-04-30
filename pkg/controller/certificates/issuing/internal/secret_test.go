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

package internal

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	applycorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	testcoreclients "github.com/cert-manager/cert-manager/test/unit/coreclients"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	testcorelisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

// These tests were formerly tested using the controllers testing package,
// however is not compatible with the Apply API call now being used by the
// SecretsManager.
// See: https://github.com/kubernetes/client-go/issues/970
func Test_SecretsManager(t *testing.T) {
	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "ca-issuer", Kind: "Issuer", Group: "foo.io"}),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(&metav1.Duration{Duration: time.Hour * 36}),
		gen.SetCertificateDNSNames("example.com"),
		gen.SetCertificateUID(apitypes.UID("test-uid")),
	)
	baseCertBundle := testcrypto.MustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
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

	tests := map[string]struct {
		certificateOptions controllerpkg.CertificateOptions
		certificate        *cmapi.Certificate
		existingSecret     *corev1.Secret

		secretData SecretData
		applyFn    func(t *testing.T) testcoreclients.ApplyFn

		expectedErr bool
	}{
		"if secret does not exists and unable to decode certificate, then error": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertBundle.Certificate,
			existingSecret:     nil,
			secretData: SecretData{
				Certificate: []byte("test-cert"), CA: []byte("test-ca"), PrivateKey: []byte("test-key"),
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(context.Context, *applycorev1.SecretApplyConfiguration, metav1.ApplyOptions) (*corev1.Secret, error) {
					t.Error("unexpected apply call")
					return nil, nil
				}
			},
			expectedErr: true,
		},

		"if secret does not exist, create new Secret, with owner disabled": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertBundle.Certificate,
			existingSecret:     nil,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key"),
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName, cmapi.AltNamesAnnotationKey: strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:  strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey: strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:       baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey: []byte("test-key"),
							cmmeta.TLSCAKey:         []byte("test-ca"),
						}).
						WithType(corev1.SecretTypeTLS)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret does not exist, create new Secret, with owner enabled": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: true},
			certificate:        baseCertBundle.Certificate,
			existingSecret:     nil,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key"),
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expUID := apitypes.UID("test-uid")

					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io", cmapi.IssuerKindAnnotationKey: "Issuer",
								cmapi.IssuerNameAnnotationKey: "ca-issuer", cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey: strings.Join(baseCertBundle.Cert.DNSNames, ","), cmapi.IPSANAnnotationKey: strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey: strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{corev1.TLSCertKey: baseCertBundle.CertBytes, corev1.TLSPrivateKeyKey: []byte("test-key"), cmmeta.TLSCAKey: []byte("test-ca")}).
						WithType(corev1.SecretTypeTLS).
						WithOwnerReferences(&applymetav1.OwnerReferenceApplyConfiguration{
							APIVersion: ptr.To("cert-manager.io/v1"), Kind: ptr.To("Certificate"),
							Name: ptr.To("test"), UID: &expUID,
							Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true),
						})
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret does exist, update existing Secret and leave custom annotations and labels, with owner disabled": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertBundle.Certificate,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   gen.DefaultTestNamespace,
					Name:        "output",
					Annotations: map[string]string{"my-custom": "annotation"},
					Labels:      map[string]string{"my-custom": "label"},
				},
				Data: map[string][]byte{corev1.TLSCertKey: []byte("foo"), corev1.TLSPrivateKeyKey: []byte("foo"), cmmeta.TLSCAKey: []byte("foo")},
				Type: corev1.SecretTypeTLS,
			},
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key"),
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:       baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey: []byte("test-key"),
							cmmeta.TLSCAKey:         []byte("test-ca"),
						}).
						WithType(corev1.SecretTypeTLS)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},
		"if secret does exist, update existing Secret and leave custom annotations and labels, with owner enabled": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: true},
			certificate:        baseCertBundle.Certificate,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   gen.DefaultTestNamespace,
					Name:        "output",
					Annotations: map[string]string{"my-custom": "annotation"},
					Labels:      map[string]string{"my-custom": "label"},
				},
				Data: map[string][]byte{corev1.TLSCertKey: []byte("foo"), corev1.TLSPrivateKeyKey: []byte("foo"), cmmeta.TLSCAKey: []byte("foo")},
				Type: corev1.SecretTypeTLS,
			},
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key"),
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expUID := apitypes.UID("test-uid")
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:       baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey: []byte("test-key"),
							cmmeta.TLSCAKey:         []byte("test-ca"),
						}).
						WithType(corev1.SecretTypeTLS).
						WithOwnerReferences(&applymetav1.OwnerReferenceApplyConfiguration{
							APIVersion: ptr.To("cert-manager.io/v1"), Kind: ptr.To("Certificate"),
							Name: ptr.To("test"), UID: &expUID,
							Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true),
						})
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret does exist, update existing Secret and add annotations set in secretTemplate": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertWithSecretTemplate,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   gen.DefaultTestNamespace,
					Name:        "output",
					Annotations: map[string]string{"my-custom": "annotation"},
					Labels:      map[string]string{"my-custom": "label"},
				},
				Data: map[string][]byte{corev1.TLSCertKey: []byte("foo"), corev1.TLSPrivateKeyKey: []byte("foo"), cmmeta.TLSCAKey: []byte("foo")},
				Type: corev1.SecretTypeTLS,
			},
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key"),
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								"template":               "annotation",
								"my-custom":              "annotation-from-secret",
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{"template": "label", cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:       baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey: []byte("test-key"),
							cmmeta.TLSCAKey:         []byte("test-ca"),
						}).
						WithType(corev1.SecretTypeTLS)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret does exist, ensure that any missing base labels and annotations are added": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertWithSecretTemplate,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   gen.DefaultTestNamespace,
					Name:        "output",
					Annotations: map[string]string{"my-custom": "annotation"},
					Labels:      map[string]string{"my-custom": "label"},
				},
				Data: map[string][]byte{corev1.TLSCertKey: []byte("foo"), corev1.TLSPrivateKeyKey: []byte("foo"), cmmeta.TLSCAKey: []byte("foo")},
				Type: corev1.SecretTypeTLS,
			},
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key"),
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								"template":               "annotation",
								"my-custom":              "annotation-from-secret",
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{"template": "label", cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:       baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey: []byte("test-key"),
							cmmeta.TLSCAKey:         []byte("test-ca"),
						}).
						WithType(corev1.SecretTypeTLS)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret does not exist, create new Secret using the secret template": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: true},
			certificate:        baseCertWithSecretTemplate,
			existingSecret:     nil,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key"),
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expUID := apitypes.UID("test-uid")
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								"template":               "annotation",
								"my-custom":              "annotation-from-secret",
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true", "template": "label"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:       baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey: []byte("test-key"),
							cmmeta.TLSCAKey:         []byte("test-ca"),
						}).
						WithType(corev1.SecretTypeTLS).
						WithOwnerReferences(&applymetav1.OwnerReferenceApplyConfiguration{
							APIVersion: ptr.To("cert-manager.io/v1"), Kind: ptr.To("Certificate"),
							Name: ptr.To("test"), UID: &expUID,
							Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true),
						})
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret does not exist, create new Secret with additional output format DER": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertWithAdditionalOutputFormatDER,
			existingSecret:     nil,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes,
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:                   baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey:             baseCertBundle.PrivateKeyBytes,
							cmmeta.TLSCAKey:                     []byte("test-ca"),
							cmapi.CertificateOutputFormatDERKey: tlsDerContent,
						}).
						WithType(corev1.SecretTypeTLS)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret does not exist, create new Secret with additional output format CombinedPEM": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertWithAdditionalOutputFormatCombinedPEM,
			existingSecret:     nil,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes,
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:                           baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey:                     baseCertBundle.PrivateKeyBytes,
							cmmeta.TLSCAKey:                             []byte("test-ca"),
							cmapi.CertificateOutputFormatCombinedPEMKey: []byte(strings.Join([]string{string(baseCertBundle.PrivateKeyBytes), string(baseCertBundle.CertBytes)}, "\n")),
						}).
						WithType(corev1.SecretTypeTLS)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret does not exist, create new Secret with additional output format DER and CombinedPEM": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertWithAdditionalOutputFormats,
			existingSecret:     nil,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes,
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:                           baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey:                     baseCertBundle.PrivateKeyBytes,
							cmmeta.TLSCAKey:                             []byte("test-ca"),
							cmapi.CertificateOutputFormatDERKey:         tlsDerContent,
							cmapi.CertificateOutputFormatCombinedPEMKey: []byte(strings.Join([]string{string(baseCertBundle.PrivateKeyBytes), string(baseCertBundle.CertBytes)}, "\n")),
						}).
						WithType(corev1.SecretTypeTLS)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret exists, with tls-combined.pem and key.der but no additional formats specified": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertBundle.Certificate,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes,
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: gen.DefaultTestNamespace,
					Name:      "output",
					Annotations: map[string]string{
						"my-custom": "annotation",
					},
					Labels: map[string]string{
						"my-custom": "label",
					},
				},
				Data: map[string][]byte{
					corev1.TLSCertKey:                           []byte("foo"),
					corev1.TLSPrivateKeyKey:                     []byte("foo"),
					cmmeta.TLSCAKey:                             []byte("foo"),
					cmapi.CertificateOutputFormatDERKey:         []byte("foo"),
					cmapi.CertificateOutputFormatCombinedPEMKey: []byte("foo"),
				},
				Type: corev1.SecretTypeOpaque,
			},

			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:       baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey: baseCertBundle.PrivateKeyBytes,
							cmmeta.TLSCAKey:         []byte("test-ca"),
						}).
						WithType(corev1.SecretTypeOpaque)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret exists, with tls-combined.pem and key.der but only DER Format specified": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertWithAdditionalOutputFormatDER,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes,
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: gen.DefaultTestNamespace,
					Name:      "output",
					Annotations: map[string]string{
						"my-custom": "annotation",
					},
					Labels: map[string]string{
						"my-custom": "label",
					},
				},
				Data: map[string][]byte{
					corev1.TLSCertKey:                           []byte("foo"),
					corev1.TLSPrivateKeyKey:                     []byte("foo"),
					cmmeta.TLSCAKey:                             []byte("foo"),
					cmapi.CertificateOutputFormatDERKey:         []byte("foo"),
					cmapi.CertificateOutputFormatCombinedPEMKey: []byte("foo"),
				},
				Type: corev1.SecretTypeOpaque,
			},

			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:                   baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey:             baseCertBundle.PrivateKeyBytes,
							cmmeta.TLSCAKey:                     []byte("test-ca"),
							cmapi.CertificateOutputFormatDERKey: tlsDerContent,
						}).
						WithType(corev1.SecretTypeOpaque)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},

		"if secret exists, with tls-combined.pem and key.der but only Combined PEM Format specified": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: false},
			certificate:        baseCertWithAdditionalOutputFormatCombinedPEM,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: baseCertBundle.PrivateKeyBytes,
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: gen.DefaultTestNamespace,
					Name:      "output",
					Annotations: map[string]string{
						"my-custom": "annotation",
					},
					Labels: map[string]string{
						"my-custom": "label",
					},
				},
				Data: map[string][]byte{
					corev1.TLSCertKey:                           []byte("foo"),
					corev1.TLSPrivateKeyKey:                     []byte("foo"),
					cmmeta.TLSCAKey:                             []byte("foo"),
					cmapi.CertificateOutputFormatDERKey:         []byte("foo"),
					cmapi.CertificateOutputFormatCombinedPEMKey: []byte("foo"),
				},
				Type: corev1.SecretTypeOpaque,
			},

			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					expCnf := applycorev1.Secret("output", gen.DefaultTestNamespace).
						WithAnnotations(
							map[string]string{
								cmapi.CertificateNameKey: "test", cmapi.IssuerGroupAnnotationKey: "foo.io",
								cmapi.IssuerKindAnnotationKey: "Issuer", cmapi.IssuerNameAnnotationKey: "ca-issuer",

								cmapi.CommonNameAnnotationKey: baseCertBundle.Cert.Subject.CommonName,
								cmapi.AltNamesAnnotationKey:   strings.Join(baseCertBundle.Cert.DNSNames, ","),
								cmapi.IPSANAnnotationKey:      strings.Join(utilpki.IPAddressesToString(baseCertBundle.Cert.IPAddresses), ","),
								cmapi.URISANAnnotationKey:     strings.Join(utilpki.URLsToString(baseCertBundle.Cert.URIs), ","),
							}).
						WithLabels(map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}).
						WithData(map[string][]byte{
							corev1.TLSCertKey:                           baseCertBundle.CertBytes,
							corev1.TLSPrivateKeyKey:                     baseCertBundle.PrivateKeyBytes,
							cmmeta.TLSCAKey:                             []byte("test-ca"),
							cmapi.CertificateOutputFormatCombinedPEMKey: []byte(strings.Join([]string{string(baseCertBundle.PrivateKeyBytes), string(baseCertBundle.CertBytes)}, "\n")),
						}).
						WithType(corev1.SecretTypeOpaque)
					assert.Equal(t, expCnf, gotCnf)

					expOpts := metav1.ApplyOptions{FieldManager: "cert-manager-test", Force: true}
					assert.Equal(t, expOpts, gotOpts)

					return nil, nil
				}
			},
			expectedErr: false,
		},
		"if apply errors, expect error response": {
			certificateOptions: controllerpkg.CertificateOptions{EnableOwnerRef: true},
			certificate:        baseCertWithSecretTemplate,
			existingSecret:     nil,
			secretData: SecretData{
				Certificate: baseCertBundle.CertBytes, CA: []byte("test-ca"), PrivateKey: []byte("test-key"),
				CertificateName: "test", IssuerName: "ca-issuer", IssuerKind: "Issuer", IssuerGroup: "foo.io",
			},
			applyFn: func(t *testing.T) testcoreclients.ApplyFn {
				return func(_ context.Context, gotCnf *applycorev1.SecretApplyConfiguration, gotOpts metav1.ApplyOptions) (*corev1.Secret, error) {
					return nil, errors.New("this is an error")
				}
			},
			expectedErr: true,
		},
	}

	// TODO: add to these tests once the JKS/PKCS12 support is updated

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			secretClient := testcoreclients.NewFakeSecretsGetter(testcoreclients.SetFakeSecretsGetterApplyFn(test.applyFn(t)))

			var mod testcorelisters.FakeSecretListerModifier
			if test.existingSecret != nil {
				mod = testcorelisters.SetFakeSecretNamespaceListerGet(test.existingSecret, nil)
			} else {
				mod = testcorelisters.SetFakeSecretNamespaceListerGet(nil, apierrors.NewNotFound(corev1.Resource("secret"), "not found"))
			}
			secretLister := testcorelisters.NewFakeSecretLister(mod)

			testManager := NewSecretsManager(
				secretClient, secretLister,
				"cert-manager-test",
				test.certificateOptions.EnableOwnerRef,
			)

			err := testManager.UpdateData(context.Background(), test.certificate, test.secretData)
			if err != nil && !test.expectedErr {
				t.Errorf("expected to not get an error, but got: %v", err)
			}
			if err == nil && test.expectedErr {
				t.Errorf("expected to get an error but did not get one")
			}
		})
	}
}

func Test_getCertificateSecret(t *testing.T) {
	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-certificate"},
		Spec:       cmapi.CertificateSpec{SecretName: "test-secret"},
	}

	tests := map[string]struct {
		existingSecret *corev1.Secret
		expSecret      *corev1.Secret
	}{
		"if secret doesn't exist, expect empty secret": {
			existingSecret: nil,
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data:       make(map[string][]byte),
				Type:       corev1.SecretTypeTLS,
			},
		},
		"if secret exists, expect onlt basic metadata to be retuned, but the Type set to tls": {
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{"abc": []byte("123"), "hello-world": []byte("bar"), "tls.crt": []byte("cert"), "tls.key": []byte("key"), "ca.crt": []byte("ca")},
				Type: corev1.SecretTypeTLS,
			},
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
				},
				Data: make(map[string][]byte),
				Type: corev1.SecretTypeTLS,
			},
		},
		"if secret exists, expect only basic metadata returned, with original Type set": {
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{"abc": []byte("123"), "hello-world": []byte("bar"), "tls.crt": []byte("cert"), "tls.key": []byte("key"), "ca.crt": []byte("ca")},
				Type: corev1.SecretTypeOpaque,
			},
			expSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
				},
				Data: make(map[string][]byte),
				Type: corev1.SecretTypeOpaque,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
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
				secretClient: builder.Client.CoreV1(),
				secretLister: builder.KubeSharedInformerFactory.Secrets().Lister(),
				fieldManager: "cert-manager-test",
			}

			builder.Start()
			defer builder.Stop()

			gotSecret, err := s.getCertificateSecret(crt)
			assert.NoError(t, err)

			assert.Equal(t, test.expSecret, gotSecret, "unexpected returned secret")
		})
	}
}
