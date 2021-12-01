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

package secrettemplate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificates/internal/secretsmanager"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
)

func Test_ProcessItem(t *testing.T) {
	const fieldManager = "cert-manager-unit-tests"

	// Enable SecretTemplate feature gate. This controller will only be
	// registered if this feature gate is enabled.
	assert.NoError(t,
		utilfeature.DefaultMutableFeatureGate.Set("ExperimentalSecretApplySecretTemplateControllerMinKubernetesVTODO=true"),
	)
	t.Cleanup(func() {
		assert.NoError(t,
			utilfeature.DefaultMutableFeatureGate.Set("ExperimentalSecretApplySecretTemplateControllerMinKubernetesVTODO=false"),
		)
	})

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
		"if Certificate and Secret exists, but the Certificate has no condition, do nothing": {
			key: "test-namespace/test-name",
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
			},
			expectedAction: false,
		},
		"if Certificate and Secret exists, but the Certificate has a False Ready condition, do nothing": {
			key: "test-namespace/test-name",
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionFalse}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
			},
			expectedAction: false,
		},
		"if Certificate exists with a Ready condition, but Secret does not exist, do nothing": {
			key: "test-namespace/test-name",
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}},
				},
			},
			secret:         nil,
			expectedAction: false,
		},
		"if Certificate exists in a Ready condition, Secret exists and matches the SecretTemplate but no managed fields, should reconcile Secret": {
			key: "test-namespace/test-name",
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace", Name: "test-secret",
					Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"},
				},
			},
			expectedAction: true,
		},
		"if Certificate exists in a Ready condition, Secret exists and matches the SecretTemplate but the managed fields contains more than what is in the SecretTemplate, should reconcile Secret": {
			key: "test-namespace/test-name",
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}},
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
			},
			expectedAction: true,
		},
		"if Certificate exists in a Ready condition, Secret exists and matches the SecretTemplate but the managed fields are managed by another manager, should reconcile Secret": {
			key: "test-namespace/test-name",
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}},
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
			},
			expectedAction: true,
		},
		"if Certificate exists in a Ready condition, Secret exists and matches the SecretTemplate with the correct managed fields, should do nothing": {
			key: "test-namespace/test-name",
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}},
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
			},
			expectedAction: false,
		},
		"if Certificate exists in a Ready condition, Secret exists but does not match SecretTemplate, should apply the Labels and Annotations": {
			key: "test-namespace/test-name",
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-secret"},
			},
			expectedAction: true,
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

			builder.Init()

			// Register informers used by the controller using the registration wrapper.
			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			assert.NoError(t, err)

			var actionCalled bool
			w.secretsUpdateData = func(_ context.Context, _ *cmapi.Certificate, _ secretsmanager.SecretData) error {
				actionCalled = true
				return nil
			}
			w.fieldManager = fieldManager

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

func Test_secretTemplateMatchesPublicFields(t *testing.T) {
	const fieldManager = "cert-manager-unit-test"

	tests := map[string]struct {
		tmpl     *cmapi.CertificateSecretTemplate
		secret   []metav1.ManagedFieldsEntry
		expMatch bool
	}{
		"if template is nil and no managed fields, should return true": {
			tmpl:     nil,
			secret:   nil,
			expMatch: true,
		},
		"if template is nil, managed fields is not nil but not managed by cert-manager, should return true": {
			tmpl: nil,
			secret: []metav1.ManagedFieldsEntry{{
				Manager: "not-cert-manager", FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:bar": {}
							},
							"f:labels": {
								"f:123": {}
							}
						}}`),
				}},
			},
			expMatch: true,
		},
		"if template is nil, managed fields is not nil but fields are nil, should return true": {
			tmpl:     nil,
			secret:   []metav1.ManagedFieldsEntry{{Manager: fieldManager, FieldsV1: nil}},
			expMatch: true,
		},
		"if template is not-nil but managed fields is nil, should return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo": "bar"},
				Labels:      map[string]string{"abc": "123"},
			},
			secret:   nil,
			expMatch: false,
		},
		"if template is nil but managed fields is not nil, should return false": {
			tmpl: nil,
			secret: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
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
			expMatch: false,
		},
		"if template annotations do not match managed fields, should return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo3": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expMatch: false,
		},
		"if template labels do not match managed fields, should return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:erg": {}
							}
						}}`),
				}},
			},
			expMatch: false,
		},
		"if template annotations and labels match managed fields, should return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expMatch: true,
		},
		"if template annotations is a subset of managed fields, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {},
								"f:foo3": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expMatch: false,
		},
		"if template labels is a subset of managed fields, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {},
								"f:ghi": {}
							}
						}}`),
				}},
			},
			expMatch: false,
		},
		"if managed fields annotations is a subset of template, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2", "foo3": "bar3"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expMatch: false,
		},
		"if managed fields labels is a subset of template, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456", "ghi": "789"},
			},
			secret: []metav1.ManagedFieldsEntry{{
				Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
			},
			expMatch: false,
		},
		"if managed fields matches template but is split across multiple managed fields, should return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2", "foo3": "bar3"},
				Labels:      map[string]string{"abc": "123", "def": "456", "ghi": "789"},
			},
			secret: []metav1.ManagedFieldsEntry{
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:labels": {
								"f:ghi": {}
							}
						}}`),
				}},
				{Manager: fieldManager, FieldsV1: &metav1.FieldsV1{
					Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo3": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
				}},
				{Manager: fieldManager,
					FieldsV1: &metav1.FieldsV1{
						Raw: []byte(`{"f:metadata": {
							"f:annotations": {
								"f:foo1": {},
								"f:foo2": {}
							},
							"f:labels": {
								"f:abc": {},
								"f:def": {}
							}
						}}`),
					}},
			},
			expMatch: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := &controller{fieldManager: fieldManager}

			match, err := c.secretTemplateMatchesManagedFields(
				&cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretTemplate: test.tmpl}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{ManagedFields: test.secret}},
			)
			assert.NoError(t, err)
			assert.Equal(t, test.expMatch, match,
				"Template=%v Secret=%v", test.tmpl, test.secret)
		})
	}
}

func Test_secretTemplateMatchesSecret(t *testing.T) {
	tests := map[string]struct {
		tmpl     *cmapi.CertificateSecretTemplate
		secret   *corev1.Secret
		expMatch bool
	}{
		"if SecretTemplate is nil, Secret Annotations and Labels are nil, return true": {
			tmpl:     nil,
			secret:   &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: nil, Labels: nil}},
			expMatch: true,
		},
		"if SecretTemplate is nil, Secret Annotations are nil, Labels are non-nil, return true": {
			tmpl:     nil,
			secret:   &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: nil, Labels: map[string]string{"foo": "bar"}}},
			expMatch: true,
		},
		"if SecretTemplate is nil, Secret Annotations are non-nil, Labels are nil, return true": {
			tmpl:     nil,
			secret:   &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"foo": "bar"}, Labels: nil}},
			expMatch: true,
		},
		"if SecretTemplate is nil, Secret Annotations and Labels are non-nil, return true": {
			tmpl: nil,
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo": "bar"},
				Labels:      map[string]string{"bar": "foo"},
			}},
			expMatch: true,
		},
		"if SecretTemplate is non-nil, Secret Annotations match but Labels are nil, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      nil,
			}},
			expMatch: false,
		},
		"if SecretTemplate is non-nil, Secret Labels match but Annotations are nil, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: nil,
				Labels:      map[string]string{"abc": "123", "def": "456"},
			}},
			expMatch: false,
		},
		"if SecretTemplate is non-nil, Secret Labels match but Annotations don't match keys, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo2": "bar1", "foo1": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			}},
			expMatch: false,
		},
		"if SecretTemplate is non-nil, Secret Annoations match but Labels don't match keys, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"def": "123", "abc": "456"},
			}},
			expMatch: false,
		},
		"if SecretTemplate is non-nil, Secret Labels match but Annotations don't match values, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar2", "foo2": "bar1"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			}},
			expMatch: false,
		},
		"if SecretTemplate is non-nil, Secret Annotations match but Labels don't match values, return false": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "456", "def": "123"},
			}},
			expMatch: false,
		},
		"if SecretTemplate is non-nil, Secret Annotations and Labels match, return true": {
			tmpl: &cmapi.CertificateSecretTemplate{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			},
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"foo1": "bar1", "foo2": "bar2"},
				Labels:      map[string]string{"abc": "123", "def": "456"},
			}},
			expMatch: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expMatch,
				secretTemplateMatchesSecret(&cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretTemplate: test.tmpl}}, test.secret),
				"Template=%v Secret=%v", test.tmpl, test.secret,
			)
		})
	}
}
