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

package keymanager

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func mustGenerateRSA(t *testing.T, keySize int) []byte {
	pk, err := pki.GenerateRSAPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	d, err := pki.EncodePKCS8PrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustGenerateECDSA(t *testing.T, keySize int) []byte {
	pk, err := pki.GenerateECPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	d, err := pki.EncodePKCS8PrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func relaxedSecretMatcher(l coretesting.Action, r coretesting.Action) error {
	objL := l.(coretesting.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
	objR := r.(coretesting.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
	for k := range objL.Data {
		objL.Data[k] = []byte("something")
	}
	for k := range objR.Data {
		objR.Data[k] = []byte("something")
	}
	if diff := cmp.Diff(objL, objR); diff != "" {
		return fmt.Errorf("unexpected difference between actions (-want +got):\n%s", diff)
	}
	return nil
}

func TestProcessItem(t *testing.T) {
	ownedSecretWithName := func(namespace, name, owner string, data map[string][]byte) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels: map[string]string{
				cmapi.IsNextPrivateKeySecretLabelKey:      "true",
				cmapi.PartOfCertManagerControllerLabelKey: "true",
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: owner, UID: types.UID(owner)},
				}, certificateGvk),
			},
		},
			Data: data,
		}
	}
	ownerRefTo := func(name string) []metav1.OwnerReference {
		return []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: name, UID: types.UID(name)},
		}, certificateGvk)}
	}
	tests := map[string]struct {
		// key that should be passed to ProcessItem.
		// if not set, the 'namespace/name' of the 'Certificate' field will be used.
		// if neither is set, the key will be ""
		key types.NamespacedName

		// Certificate to be synced for the test.
		// if not set, the 'key' will be passed to ProcessItem instead.
		certificate *cmapi.Certificate

		secrets []runtime.Object

		// Request, if set, will exist in the apiserver before the test is run.
		requests []*cmapi.CertificateRequest

		expectedActions []testpkg.Action

		expectedEvents []string

		// err is the expected error text returned by the controller, if any.
		err string
	}{
		"do nothing if an empty 'key' is used": {},
		"do nothing if an invalid 'key' is used": {
			key: types.NamespacedName{
				Namespace: "abc",
				Name:      "def/ghi",
			},
		},
		"do nothing if a key references a Certificate that does not exist": {
			key: types.NamespacedName{
				Namespace: "namespace",
				Name:      "name",
			},
		},
		"do nothing if Certificate has 'Issuing' condition set to 'false'": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionFalse,
						},
					},
				},
			},
		},
		"do nothing if Certificate has no 'Issuing' condition": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{},
				},
			},
		},
		"create a secret and record its name if issuing is true": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			expectedEvents: []string{`Normal Generated Stored new private key in temporary Secret resource "test-notrandom"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewGetAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"testns",
					"test",
				)),
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"status",
					"testns",
					&cmapi.Certificate{
						ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
						Status: cmapi.CertificateStatus{
							NextPrivateKeySecretName: new("test-notrandom"),
							Conditions: []cmapi.CertificateCondition{
								{
									Type:   cmapi.CertificateConditionIssuing,
									Status: cmmeta.ConditionTrue,
								},
							},
						},
					},
				)),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:       "testns",
							GenerateName:    "test-",
							Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
							OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"}}, certificateGvk)},
						},
						Data: map[string][]byte{"tls.key": nil},
					},
				), relaxedSecretMatcher),
			},
		},
		"create a secret under a generated name if status.nextPrivateKeySecretName names a Secret that does not exist": {
			// The name must not be reused. It could be the spec.secretName of
			// another Certificate that has not issued yet; creating it here would
			// let this Certificate delete that Secret, or sign with its key.
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			expectedEvents: []string{`Normal Generated Stored new private key in temporary Secret resource "test-notrandom"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewGetAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"testns",
					"test",
				)),
				testpkg.NewAction(coretesting.NewGetAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:       "testns",
							GenerateName:    "test-",
							Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
							OwnerReferences: ownerRefTo("test"),
						},
						Data: map[string][]byte{"tls.key": nil},
					},
				), relaxedSecretMatcher),
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"status",
					"testns",
					&cmapi.Certificate{
						ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
						Status: cmapi.CertificateStatus{
							NextPrivateKeySecretName: new("test-notrandom"),
							Conditions: []cmapi.CertificateCondition{
								{
									Type:   cmapi.CertificateConditionIssuing,
									Status: cmmeta.ConditionTrue,
								},
							},
						},
					},
				)),
			},
		},
		// The name in status.nextPrivateKeySecretName cannot be trusted: writing
		// the certificates/status subresource is a weaker permission than
		// reading Secrets. The keymanager must not adopt a Secret it does not
		// own, and must not keep retrying the same name, because the consumers
		// of the field reject that Secret and issuance would never recover.
		"create a secret under a generated name if status.nextPrivateKeySecretName names a Secret not owned by the Certificate": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			// The Secret is labeled and owned by another Certificate, so only the
			// owner UID comparison rejects it.
			secrets: []runtime.Object{ownedSecretWithName("testns", "fixed-name", "other", nil)},
			expectedEvents: []string{
				`Warning NotOwned Ignoring status.nextPrivateKeySecretName "fixed-name": the Secret is not owned by this Certificate`,
				`Normal Generated Stored new private key in temporary Secret resource "test-notrandom"`,
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewGetAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"testns",
					"test",
				)),
				testpkg.NewAction(coretesting.NewGetAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:       "testns",
							GenerateName:    "test-",
							Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
							OwnerReferences: ownerRefTo("test"),
						},
						Data: map[string][]byte{"tls.key": nil},
					},
				), relaxedSecretMatcher),
				// The status field is repointed at the new Secret, which is
				// what lets the requestmanager and issuing controllers proceed.
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"status",
					"testns",
					&cmapi.Certificate{
						ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
						Status: cmapi.CertificateStatus{
							NextPrivateKeySecretName: new("test-notrandom"),
							Conditions: []cmapi.CertificateCondition{
								{
									Type:   cmapi.CertificateConditionIssuing,
									Status: cmmeta.ConditionTrue,
								},
							},
						},
					},
				)),
			},
		},
		"clear nextPrivateKeySecretName if rotationPolicy is Never and the existing key does not match the spec": {
			// The keymanager cannot make a next private key here, so a stale or
			// untrusted name must not stay in the status field.
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Spec: cmapi.CertificateSpec{
					SecretName: "output",
					PrivateKey: &cmapi.CertificatePrivateKey{RotationPolicy: cmapi.RotationPolicyNever},
				},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "output"},
				Data:       map[string][]byte{"tls.key": mustGenerateECDSA(t, pki.ECCurve256)},
			}},
			expectedEvents: []string{`Warning CannotRegenerateKey User intervention required: existing private key in Secret "output" does not match requirements on Certificate resource, mismatching fields: [spec.privateKey.algorithm], but cert-manager cannot create new private key as the Certificate's .spec.privateKey.rotationPolicy is unset or set to Never. To allow cert-manager to create a new private key you can set .spec.privateKey.rotationPolicy to 'Always' (this will result in the private key being regenerated every time a cert is renewed) `},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"status",
					"testns",
					&cmapi.Certificate{
						ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
						Status: cmapi.CertificateStatus{
							Conditions: []cmapi.CertificateCondition{
								{
									Type:   cmapi.CertificateConditionIssuing,
									Status: cmmeta.ConditionTrue,
								},
							},
						},
					},
				)),
			},
		},
		"if multiple owned secrets exist, delete them all": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
				ownedSecretWithName("testns", "fixed-name-2", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name-2",
				)),
			},
		},
		"if multiple owned secrets exist with one matching nextPrivateKeySecretName, preserve the matching one and delete others": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", map[string][]byte{"tls.key": mustGenerateRSA(t, 2048)}),
				ownedSecretWithName("testns", "fixed-name-2", "test", nil),
				ownedSecretWithName("testns", "fixed-name-3", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name-2",
				)),
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name-3",
				)),
			},
		},
		"if multiple owned secrets exist but none match nextPrivateKeySecretName, delete all": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("expected-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
				ownedSecretWithName("testns", "fixed-name-2", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name-2",
				)),
			},
		},
		"if a named and owned secret exists but contains no data, delete it": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
			},
		},
		"if an owned secret exists but nextPrivateKeySecretName is not set, set it": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"status",
					"testns",
					&cmapi.Certificate{
						ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
						Status: cmapi.CertificateStatus{
							NextPrivateKeySecretName: new("fixed-name"),
							Conditions: []cmapi.CertificateCondition{
								{
									Type:   cmapi.CertificateConditionIssuing,
									Status: cmmeta.ConditionTrue,
								},
							},
						},
					},
				)),
			},
		},
		"if an owned secret exists but has a different name to nextPrivateKeySecretName, repoint nextPrivateKeySecretName at it": {
			// Deleting the Secret instead would let anyone able to write the
			// certificates/status subresource force a key rotation on demand,
			// and would race the Secret informer after the keymanager itself
			// repoints the field.
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name-2"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"status",
					"testns",
					&cmapi.Certificate{
						ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
						Status: cmapi.CertificateStatus{
							NextPrivateKeySecretName: new("fixed-name"),
							Conditions: []cmapi.CertificateCondition{
								{
									Type:   cmapi.CertificateConditionIssuing,
									Status: cmmeta.ConditionTrue,
								},
							},
						},
					},
				)),
			},
		},
		"if an owned secret exists but contains invalid private key data, delete it": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", map[string][]byte{"tls.key": []byte("invalid")}),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
			},
		},
		"if an owned secret exists but contains 'non-matching' data, delete it'": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", map[string][]byte{"tls.key": mustGenerateECDSA(t, pki.ECCurve256)}),
			},
			expectedEvents: []string{"Normal Deleted Regenerating private key due to change in fields: [spec.privateKey.algorithm]"},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
			},
		},
		"if an owned secret exists and contains data valid for the spec, do nothing'": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", map[string][]byte{"tls.key": mustGenerateRSA(t, 2048)}),
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create and initialise a new unit test builder
			builder := &testpkg.Builder{
				T:               t,
				ExpectedEvents:  test.expectedEvents,
				ExpectedActions: test.expectedActions,
				StringGenerator: func(i int) string { return "notrandom" },
			}
			if test.certificate != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.certificate)
			}
			if test.secrets != nil {
				builder.KubeObjects = append(builder.KubeObjects, test.secrets...)
			}
			for _, req := range test.requests {
				builder.CertManagerObjects = append(builder.CertManagerObjects, req)
			}
			builder.Init()

			// Register informers used by the controller using the registration wrapper
			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}
			// Start the informers and begin processing updates
			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == (types.NamespacedName{}) && test.certificate != nil {
				key = types.NamespacedName{
					Name:      test.certificate.Name,
					Namespace: test.certificate.Namespace,
				}
			}

			// Call ProcessItem
			err = w.controller.ProcessItem(t.Context(), key)
			switch {
			case err != nil:
				if test.err != err.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), test.err)
				}
			default:
				if test.err != "" {
					t.Errorf("got no error but expected: %s", test.err)
				}
			}

			if err := builder.AllEventsCalled(); err != nil {
				builder.T.Error(err)
			}
			if err := builder.AllActionsExecuted(); err != nil {
				builder.T.Error(err)
			}
		})
	}
}
