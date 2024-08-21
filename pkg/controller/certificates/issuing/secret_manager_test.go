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

package issuing

import (
	"context"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing/internal"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
)

func Test_ensureSecretData(t *testing.T) {
	const fieldManager = "cert-manager-unit-tests"

	pk := testcrypto.MustCreatePEMPrivateKey(t)
	cert := testcrypto.MustCreateCert(t, pk, &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "test"}})
	block, _ := pem.Decode(pk)
	pkDER := block.Bytes
	combinedPEM := append(append(pk, '\n'), cert...)

	tests := map[string]struct {
		// key that should be passed to ProcessItem.
		// if not set, the 'namespace/name' of the 'Certificate' field will be used.
		// if neither is set, the key will be "".
		key types.NamespacedName

		// cert is the optional cert to be loaded to fake clientset.
		cert *cmapi.Certificate

		// secret is the optional secret to be loaded into the fake clientset.
		secret *corev1.Secret

		// expectedAction is true if the test expects that the controller should
		// reconcile the Secret.
		expectedAction bool

		// enableOwnerRef is passed to the post issuance policy checks.
		enableOwnerRef bool
	}{
		"if 'key' is empty, should do nothing and not error": {
			expectedAction: false,
		},
		"if 'key' is an invalid value, should do nothing and not error": {
			key: types.NamespacedName{
				Namespace: "abc",
				Name:      "def/ghi",
			},
			expectedAction: false,
		},
		"if 'key' references a Certificate that doesn't exist, should do nothing and not error": {
			key: types.NamespacedName{
				Namespace: "random-namespace",
				Name:      "random-certificate",
			},
			expectedAction: false,
		},
		"if Certificate and Secret exists, but the Secret contains no certificate or private key data, do nothing": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data:       map[string][]byte{},
			},
			expectedAction: false,
		},
		"if Certificate and Secret exists, but the Secret contains no certificate data, do nothing": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data: map[string][]byte{
					"tls.key": pk,
				},
			},
			expectedAction: false,
		},
		"if Certificate and Secret exists, but the Secret contains no private key data, do nothing": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data: map[string][]byte{
					"tls.cert": cert,
				},
			},
			expectedAction: false,
		},
		"if Certificate and Secret exists, but the Certificate has a True Issuing condition, do nothing": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: false,
		},
		"if Certificate exists without a Issuing condition, but Secret does not exist, do nothing": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{},
			},
			secret:         nil,
			expectedAction: false,
		},
		"if Certificate exists in a false Issuing condition, Secret exists and matches the SecretTemplate but no managed fields, should reconcile Secret": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate exists in a false Issuing condition, Secret exists and matches the SecretTemplate but the managed fields contains more than what is in the SecretTemplate, should reconcile Secret": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
					ManagedFields: []metav1.ManagedFieldsEntry{{
						Manager: fieldManager,
						FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:cert-manager.io/common-name": {},
								"f:cert-manager.io/alt-names": {},
								"f:cert-manager.io/ip-sans": {},
								"f:cert-manager.io/uri-sans": {},
								"f:foo": {},
								"f:another-annotation": {}
							},
							"f:labels": {
								"f:controller.cert-manager.io/fao": {},
								"f:abc": {},
								"f:another-label": {}
							}
						}}`),
						},
					}},
				},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate exists in a false Issuing condition, Secret exists and matches the SecretTemplate but the managed fields are managed by another manager, should reconcile Secret": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
					ManagedFields: []metav1.ManagedFieldsEntry{{
						Manager: "not-cert-manager",
						FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:cert-manager.io/common-name": {},
								"f:cert-manager.io/alt-names": {},
								"f:cert-manager.io/ip-sans": {},
								"f:cert-manager.io/uri-sans": {},
								"f:foo": {}
							},
							"f:labels": {
								"f:controller.cert-manager.io/fao": {},
								"f:abc": {}
							}
						}}`),
						}},
					},
				},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate exists in a false Issuing condition, Secret exists and matches the SecretTemplate with the correct managed fields and base labels, should do nothing": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName: "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"},
						Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"},
					Labels:      map[string]string{"abc": "123", cmapi.PartOfCertManagerControllerLabelKey: "true"},
					ManagedFields: []metav1.ManagedFieldsEntry{{
						Manager: fieldManager,
						FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:cert-manager.io/common-name": {},
								"f:cert-manager.io/alt-names": {},
								"f:cert-manager.io/ip-sans": {},
								"f:cert-manager.io/uri-sans": {},
								"f:foo": {}
							},
							"f:labels": {
								"f:controller.cert-manager.io/fao": {},
								"f:abc": {}
							}
						}}`),
						}},
					},
				},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: false,
		},
		"if Certificate exists in a false Issuing condition, Secret exists but does not match SecretTemplate, should apply the Labels and Annotations": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse},
						{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate exists in a false Issuing condition, Secret exists but is missing the required label, apply the label": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse},
						{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					Labels: map[string]string{"foo": "bar"}},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate exists in a false Issuing condition, Secret exists with some labels, but is missing the required label, apply the label": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse},
						{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate with combined pem and Secret exists, but the Secret doesn't have combined pem, should apply the combined pem": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName: "test-secret",
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate with der and Secret exists, but the Secret doesn't have der, should apply the der": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName: "test-secret",
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "DER"},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate with combined pem and der, and Secret exists, but the Secret doesn't have combined pem or der, should apply the combined pem and der": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName: "test-secret",
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
						{Type: "DER"},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"}},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate with combined pem and der, and Secret exists with combined pem and der with managed fields, should do nothing": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName: "test-secret",
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{
						{Type: "CombinedPEM"},
						{Type: "DER"},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					ManagedFields: []metav1.ManagedFieldsEntry{{
						Manager: fieldManager,
						FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{
								"f:metadata": {
									"f:labels": {
										"f:controller.cert-manager.io/fao": {}
									},
									"f:annotations": {
										"f:cert-manager.io/common-name": {},
										"f:cert-manager.io/alt-names": {},
										"f:cert-manager.io/ip-sans": {},
										"f:cert-manager.io/uri-sans": {}
									},
									"f:ownerReferences": {
										"k:{\"uid\":\"uid-123\"}": {}
									}
								},
								"f:data": {
									"f:tls-combined.pem": {},
									"f:key.der": {}
								}
							}`),
						},
					}},
				},
				Data: map[string][]byte{
					"tls.crt":          cert,
					"tls.key":          pk,
					"tls-combined.pem": combinedPEM,
					"key.der":          pkDER,
				},
			},
			expectedAction: false,
		},
		"if Certificate with no combined pem or der, and Secret exists with combined pem and der managed by field manager, should apply to remove them": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:              "test-secret",
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					ManagedFields: []metav1.ManagedFieldsEntry{{
						Manager: fieldManager,
						FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{
								"f:metadata": {
									"f:labels": {
										"f:controller.cert-manager.io/fao": {}
									},
									"f:annotations": {
										"f:cert-manager.io/common-name": {},
										"f:cert-manager.io/alt-names": {},
										"f:cert-manager.io/ip-sans": {},
										"f:cert-manager.io/uri-sans": {}
									},
									"f:ownerReferences": {
										"k:{\"uid\":\"uid-123\"}": {}
									}
								},
								"f:data": {
									"f:tls-combined.pem": {},
									"f:key.der": {}
								}
							}`),
						},
					}},
				},
				Data: map[string][]byte{
					"tls.crt":          cert,
					"tls.key":          pk,
					"tls-combined.pem": combinedPEM,
					"key.der":          pkDER,
				},
			},
			expectedAction: true,
		},

		"enabledOwnerRef=false if Secret has owner reference to Certificate owned by field manager, expect action": {
			enableOwnerRef: false,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec:       cmapi.CertificateSpec{SecretName: "test-secret"},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{"tls.crt": cert, "tls.key": pk, "key.der": pkDER},
			},
			expectedAction: true,
		},
		"enabledOwnerRef=true if Secret has owner reference to Certificate owned by field manager, expect no action": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec:       cmapi.CertificateSpec{SecretName: "test-secret"},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{"tls.crt": cert, "tls.key": pk, "key.der": pkDER},
			},
			expectedAction: false,
		},
		"refresh secrets when keystore is not defined and the secret has keystore/truststore fields": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-234")},
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					SecretName: "test-secret",
				}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "test-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-234"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: pk,
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, pk,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
					cmapi.PKCS12TruststoreKey: []byte("SomeData"),
				},
			},
			expectedAction: true,
		},
		"refresh secrets when JKS keystore is defined and the secret does not have keystore/truststore fields": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					SecretName: "something",
					Keystores: &cmapi.CertificateKeystores{
						JKS: &cmapi.JKSKeystore{
							Create: true,
						},
					},
				}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something", Namespace: "test-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: pk,
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, pk,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			expectedAction: true,
		},
		"refresh secrets when JKS keystore is defined, create is disabled and the secret has keystore/truststore fields": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					SecretName: "something",
					Keystores: &cmapi.CertificateKeystores{
						JKS: &cmapi.JKSKeystore{
							Create: false,
						},
					},
				}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something", Namespace: "test-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: pk,
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, pk,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
					cmapi.JKSTruststoreKey: []byte("SomeData"),
				},
			},
			expectedAction: true,
		},
		"refresh secrets when JKS keystore is null and the secret has keystore/truststore fields": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					SecretName: "something",
					Keystores: &cmapi.CertificateKeystores{
						JKS: nil,
					},
				}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something", Namespace: "test-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: pk,
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, pk,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
					cmapi.JKSTruststoreKey: []byte("SomeData"),
				},
			},
			expectedAction: true,
		},
		"do nothing when JKS keystore is defined and create field is set to false": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					SecretName: "something",
					Keystores: &cmapi.CertificateKeystores{
						JKS: &cmapi.JKSKeystore{
							Create: false,
						},
					},
				}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something", Namespace: "test-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: pk,
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, pk,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			expectedAction: false,
		},
		"refresh secret when PKCS12 keystore is defined and the secret does not have keystore/truststore fields": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					SecretName: "something",
					Keystores: &cmapi.CertificateKeystores{
						PKCS12: &cmapi.PKCS12Keystore{
							Create: true,
						},
					},
				}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something", Namespace: "test-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: pk,
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, pk,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			expectedAction: true,
		},
		"refresh secret when PKCS12 keystore is defined, create is disabled and the secret has keystore/truststore fields": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					SecretName: "something",
					Keystores: &cmapi.CertificateKeystores{
						PKCS12: &cmapi.PKCS12Keystore{
							Create: false,
						},
					},
				}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something", Namespace: "test-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: pk,
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, pk,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
					cmapi.PKCS12TruststoreKey: []byte("SomeData"),
				},
			},
			expectedAction: true,
		},
		"refresh secret when PKCS12 keystore is null and the secret has keystore/truststore fields": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					SecretName: "something",
					Keystores: &cmapi.CertificateKeystores{
						PKCS12: nil,
					},
				}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something", Namespace: "test-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: pk,
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, pk,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
					cmapi.PKCS12TruststoreKey: []byte("SomeData"),
				},
			},
			expectedAction: true,
		},
		"do nothing when PKCS12 keystore is defined and the create is set to false": {
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec: cmapi.CertificateSpec{
					CommonName: "example.com",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "testissuer",
						Kind:  "IssuerKind",
						Group: "group.example.com",
					},
					SecretName: "something",
					Keystores: &cmapi.CertificateKeystores{
						PKCS12: &cmapi.PKCS12Keystore{
							Create: false,
						},
					},
				}},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "something", Namespace: "test-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "testissuer",
						cmapi.IssuerKindAnnotationKey:  "IssuerKind",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
					Labels: map[string]string{cmapi.PartOfCertManagerControllerLabelKey: "true"},
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
							{"f:metadata": {
								"f:labels": {
									"f:controller.cert-manager.io/fao": {}
								},
								"f:annotations": {
									"f:cert-manager.io/common-name": {},
									"f:cert-manager.io/alt-names": {},
									"f:cert-manager.io/ip-sans": {},
									"f:cert-manager.io/uri-sans": {}
								},
								"f:ownerReferences": {
									"k:{\"uid\":\"uid-123\"}": {}
								}
							}}`),
						}},
					},
				},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: pk,
					corev1.TLSCertKey: testcrypto.MustCreateCert(t, pk,
						&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.com"}},
					),
				},
			},
			expectedAction: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create and initialise a new unit test builder.
			builder := &testpkg.Builder{
				T: t,
			}
			if test.cert != nil {
				// Ensures cert is loaded into the builder's fake clientset.
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.cert)
			}
			if test.secret != nil {
				// Ensures secret is loaded into the builder's fake clientset.
				builder.KubeObjects = append(builder.KubeObjects, test.secret)
			}

			// Initialise with RESTConfig which is used to discover the User Agent.
			builder.InitWithRESTConfig()
			builder.EnableOwnerRef = test.enableOwnerRef

			// Register informers used by the controller using the registration wrapper.
			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			assert.NoError(t, err)

			var actionCalled bool
			w.secretsUpdateData = func(_ context.Context, _ *cmapi.Certificate, _ internal.SecretData) error {
				actionCalled = true
				return nil
			}
			w.postIssuancePolicyChain = policies.NewSecretPostIssuancePolicyChain(test.enableOwnerRef, fieldManager)

			// Start the informers and begin processing updates.
			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == (types.NamespacedName{}) && test.cert != nil {
				key = types.NamespacedName{
					Name:      test.cert.Name,
					Namespace: test.cert.Namespace,
				}
			}

			// Call ProcessItem
			err = w.controller.ProcessItem(context.Background(), key)
			assert.NoError(t, err)

			if err := builder.AllActionsExecuted(); err != nil {
				builder.T.Error(err)
			}

			assert.Equal(t, test.expectedAction, actionCalled, "unexpected Secret reconcile called")
		})
	}
}
