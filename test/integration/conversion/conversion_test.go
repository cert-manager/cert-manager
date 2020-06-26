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

package conversion

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/diff"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jetstack/cert-manager/pkg/api"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha3"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/integration/framework"
)

func TestConversion(t *testing.T) {
	tests := map[string]struct {
		input     runtime.Object
		targetGVK schema.GroupVersionKind
		output    runtime.Object
	}{
		"should convert Certificates from v1alpha2 to v1alpha3": {
			input: &v1alpha2.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha2.CertificateSpec{
					SecretName: "something",
					IssuerRef: cmmeta.ObjectReference{
						Name: "issuername",
					},
				},
			},
			targetGVK: v1alpha3.SchemeGroupVersion.WithKind("Certificate"),
			output: &v1alpha3.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.CertificateSpec{
					SecretName: "something",
					IssuerRef: cmmeta.ObjectReference{
						Name: "issuername",
					},
				},
			},
		},
		"should convert CertificateRequest from v1alpha2 to v1alpha3": {
			input: &v1alpha2.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha2.CertificateRequestSpec{
					// validating webhook isn't currently configured in test
					// environment so this passes validation.
					CSRPEM: []byte("a"),
					IssuerRef: cmmeta.ObjectReference{
						Name: "issuername",
					},
				},
			},
			targetGVK: v1alpha3.SchemeGroupVersion.WithKind("CertificateRequest"),
			output: &v1alpha3.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.CertificateRequestSpec{
					// validating webhook isn't currently configured in test
					// environment so this passes validation.
					CSRPEM: []byte("a"),
					IssuerRef: cmmeta.ObjectReference{
						Name: "issuername",
					},
				},
			},
		},
		"should convert Certificate from v1alpha2 to v1beta1": {
			input: &v1alpha2.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha2.CertificateSpec{
					SecretName:   "abc",
					Organization: []string{"test"},
					IssuerRef: cmmeta.ObjectReference{
						Name: "issuername",
					},
				},
			},
			targetGVK: v1beta1.SchemeGroupVersion.WithKind("Certificate"),
			output: &v1beta1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1beta1.CertificateSpec{
					SecretName: "abc",
					Subject: &v1beta1.X509Subject{
						Organizations: []string{"test"},
					},
					IssuerRef: cmmeta.ObjectReference{
						Name: "issuername",
					},
				},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config, stop := framework.RunControlPlane(t)
			defer stop()

			cl, err := client.New(config, client.Options{Scheme: api.Scheme})
			if err != nil {
				t.Fatal(err)
			}

			if err := cl.Create(context.Background(), test.input); err != nil {
				t.Fatal(err)
			}
			meta := test.input.(metav1.ObjectMetaAccessor)

			convertedObj, err := api.Scheme.New(test.targetGVK)
			if err != nil {
				t.Fatal(err)
			}

			if err := cl.Get(context.Background(), client.ObjectKey{Name: meta.GetObjectMeta().GetName(), Namespace: meta.GetObjectMeta().GetNamespace()}, convertedObj); err != nil {
				t.Fatalf("failed to fetch object in expected API version: %v", err)
			}

			convertedObjMeta := convertedObj.(metav1.ObjectMetaAccessor)
			convertedObjMeta.GetObjectMeta().SetCreationTimestamp(metav1.Time{})
			convertedObjMeta.GetObjectMeta().SetGeneration(0)
			convertedObjMeta.GetObjectMeta().SetUID("")
			convertedObjMeta.GetObjectMeta().SetSelfLink("")
			convertedObjMeta.GetObjectMeta().SetResourceVersion("")

			if !equality.Semantic.DeepEqual(test.output, convertedObj) {
				t.Errorf("unexpected output: %s", diff.ObjectReflectDiff(test.output, convertedObj))
			}
		})
	}
}
