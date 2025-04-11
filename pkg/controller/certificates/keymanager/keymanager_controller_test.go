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
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/kr/pretty"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

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
	if !reflect.DeepEqual(objL, objR) {
		return fmt.Errorf("unexpected difference between actions: %s", pretty.Diff(objL, objR))
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
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"status",
					"testns",
					&cmapi.Certificate{
						ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
						Status: cmapi.CertificateStatus{
							NextPrivateKeySecretName: ptr.To("test-notrandom"),
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
		"create a secret using the already allocated name if it is set": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: ptr.To("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			expectedEvents: []string{`Normal Generated Stored new private key in temporary Secret resource "fixed-name"`},
			expectedActions: []testpkg.Action{
				testpkg.NewCustomMatch(coretesting.NewCreateAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:       "testns",
							Name:            "fixed-name",
							Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
							OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"}}, certificateGvk)},
						},
						Data: map[string][]byte{"tls.key": nil},
					},
				), relaxedSecretMatcher),
			},
		},
		// TODO: in this case we should adapt the controller behaviour to unset the nextPrivateKeySecretName to
		//  gracefully recover
		"error if an existing Secret exists and is named as status.nextPrivateKeySecretName but it is not owned by the Certificate": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: ptr.To("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "fixed-name"}}},
			expectedActions: []testpkg.Action{
				testpkg.NewCustomMatch(coretesting.NewCreateAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:       "testns",
							Name:            "fixed-name",
							Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
							OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"}}, certificateGvk)},
						},
						Data: map[string][]byte{"tls.key": nil},
					},
				), relaxedSecretMatcher),
			},
			err: `secrets "fixed-name" already exists`,
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
		// TODO: change this behaviour to not delete the named nextPrivateKeySecretName
		"if multiple owned secrets exist, delete them all even if one is the named Secret": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: ptr.To("fixed-name"),
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
					NextPrivateKeySecretName: ptr.To("fixed-name"),
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
							NextPrivateKeySecretName: ptr.To("fixed-name"),
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
		"if an owned secret exists but has a different name to nextPrivateKeySecretName, delete it": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: ptr.To("fixed-name-2"),
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
		"if an owned secret exists but contains invalid private key data, delete it": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: ptr.To("fixed-name"),
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
					NextPrivateKeySecretName: ptr.To("fixed-name"),
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
					NextPrivateKeySecretName: ptr.To("fixed-name"),
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
			err = w.controller.ProcessItem(context.Background(), key)
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
