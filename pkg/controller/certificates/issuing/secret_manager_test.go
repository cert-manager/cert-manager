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
	"k8s.io/utils/pointer"

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
		key string

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
			key:            "abc/def/ghi",
			expectedAction: false,
		},
		"if 'key' references a Certificate that doesn't exist, should do nothing and not error": {
			key:            "random-namespace/random-certificate",
			expectedAction: false,
		},
		"if Certificate and Secret exists, but the Secret contains no certificate or private key data, do nothing": {
			key: "test-namespace/test-name",
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
			key: "test-namespace/test-name",
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
			key: "test-namespace/test-name",
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
			key: "test-namespace/test-name",
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
			key: "test-namespace/test-name",
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
			key: "test-namespace/test-name",
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
			key: "test-namespace/test-name",
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
								"f:foo": {},
								"f:another-annotation": {}
							},
							"f:labels": {
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
			key: "test-namespace/test-name",
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
								"f:foo": {}
							},
							"f:labels": {
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
		"if Certificate exists in a false Issuing condition, Secret exists and matches the SecretTemplate with the correct managed fields, should do nothing": {
			key: "test-namespace/test-name",
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
								"f:foo": {}
							},
							"f:labels": {
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
			key: "test-namespace/test-name",
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
			key: "test-namespace/test-name",
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
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate with der and Secret exists, but the Secret doesn't have der, should apply the der": {
			key: "test-namespace/test-name",
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
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate with combined pem and der, and Secret exists, but the Secret doesn't have combined pem or der, should apply the combined pem and der": {
			key: "test-namespace/test-name",
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
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": pk,
				},
			},
			expectedAction: true,
		},
		"if Certificate with combined pem and der, and Secret exists with combined pem and der with managed fields, should do nothing": {
			key: "test-namespace/test-name",
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
					ManagedFields: []metav1.ManagedFieldsEntry{{
						Manager: fieldManager,
						FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`{"f:data": {
							"f:tls-combined.pem": {},
							"f:key.der": {}
						}}`),
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
			key: "test-namespace/test-name",
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:              "test-secret",
					AdditionalOutputFormats: []cmapi.CertificateAdditionalOutputFormat{},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					ManagedFields: []metav1.ManagedFieldsEntry{{
						Manager: fieldManager,
						FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`{"f:data": {
							"f:tls-combined.pem": {},
							"f:key.der": {}
						}}`),
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
			key:            "test-namespace/test-name",
			enableOwnerRef: false,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec:       cmapi.CertificateSpec{SecretName: "test-secret"},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
                {"f:metadata": {
								"f:ownerReferences": {
                "k:{\"uid\":\"uid-123\"}": {}
							}}}`),
						}},
					},
				},
				Data: map[string][]byte{"tls.crt": cert, "tls.key": pk, "key.der": pkDER},
			},
			expectedAction: true,
		},
		"enabledOwnerRef=true if Secret has owner reference to Certificate owned by field manager, expect no action": {
			key:            "test-namespace/test-name",
			enableOwnerRef: true,
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name", UID: types.UID("uid-123")},
				Spec:       cmapi.CertificateSpec{SecretName: "test-secret"},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret",
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: "test-name", UID: types.UID("uid-123"), Controller: pointer.Bool(true), BlockOwnerDeletion: pointer.Bool(true)},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
							Raw: []byte(`
                {"f:metadata": {
								"f:ownerReferences": {
                "k:{\"uid\":\"uid-123\"}": {}
							}}}`),
						}},
					},
				},
				Data: map[string][]byte{"tls.crt": cert, "tls.key": pk, "key.der": pkDER},
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

			// Call ProcessItem
			err = w.controller.ProcessItem(context.Background(), key)
			assert.NoError(t, err)

			if err := builder.AllActionsExecuted(); err != nil {
				builder.T.Error(err)
			}
			if err := builder.AllReactorsCalled(); err != nil {
				builder.T.Error(err)
			}

			assert.Equal(t, test.expectedAction, actionCalled, "unexpected Secret reconcile called")
		})
	}
}
