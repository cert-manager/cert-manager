/*
Copyright 2026 The cert-manager Authors.

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

package certificates

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	coreinformers "k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// TestNextPrivateKeySecretSelectorRejectsUnlabeledSecret checks that the
// selector used for next private key Secret LISTs still excludes Secrets
// carrying no labels at all.
//
// The SecretsFilteredCaching feature, which is on by default, serves part of
// that LIST from a metadata-only cache that stores no labels, and charges one
// live GET against the API server for every Secret it returns. A selector such
// as labels.Everything() matches every entry in that cache, so the keymanager
// would GET every Secret in the namespace on every reconcile.
func TestNextPrivateKeySecretSelectorRejectsUnlabeledSecret(t *testing.T) {
	if NextPrivateKeySecretSelector.Matches(labels.Set{}) {
		t.Error("selector must not match a Secret with no labels, or the Secret LIST will GET every Secret in the namespace")
	}
	if !NextPrivateKeySecretSelector.Matches(labels.Set{cmapi.IsNextPrivateKeySecretLabelKey: "true"}) {
		t.Error("selector must match a next private key Secret")
	}
}

func TestGetNextPrivateKeySecret(t *testing.T) {
	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cert",
			Namespace: "testns",
			UID:       "cert-uid",
		},
		Spec: cmapi.CertificateSpec{
			SecretName: "tls-secret",
		},
		Status: cmapi.CertificateStatus{
			NextPrivateKeySecretName: new("next-pk"),
		},
	}

	// ownedSecret is what the keymanager controller creates: labeled, and with
	// crt as its controller.
	ownedSecret := func() *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "next-pk",
				Namespace: "testns",
				Labels: map[string]string{
					cmapi.IsNextPrivateKeySecretLabelKey: "true",
				},
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate")),
				},
			},
		}
	}

	tests := map[string]struct {
		secret   *corev1.Secret
		crt      *cmapi.Certificate
		wantName string
		// wantNotFound is true when the Secret must be rejected, whether it is
		// absent or fails the ownership checks.
		wantNotFound bool
	}{
		"returns a Secret owned by and labeled for the Certificate": {
			secret:   ownedSecret(),
			crt:      crt,
			wantName: "next-pk",
		},
		"rejects a Secret with no owner reference": {
			// An unrelated Secret in the same namespace, named by a principal
			// with access only to the certificates/status subresource.
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "next-pk", Namespace: "testns"},
			},
			crt:          crt,
			wantNotFound: true,
		},
		"rejects a Secret labeled but owned by a different Certificate": {
			secret: func() *corev1.Secret {
				s := ownedSecret()
				other := crt.DeepCopy()
				other.Name = "other-cert"
				other.UID = "other-uid"
				s.OwnerReferences = []metav1.OwnerReference{
					*metav1.NewControllerRef(other, cmapi.SchemeGroupVersion.WithKind("Certificate")),
				}
				return s
			}(),
			crt:          crt,
			wantNotFound: true,
		},
		"rejects a Secret whose owner reference is not a controller reference": {
			// metav1.IsControlledBy only accepts an owner reference with
			// controller: true. A plain owner reference is not enough.
			secret: func() *corev1.Secret {
				s := ownedSecret()
				s.OwnerReferences[0].Controller = new(false)
				return s
			}(),
			crt:          crt,
			wantNotFound: true,
		},
		"rejects a Secret owned by the Certificate but missing the label": {
			secret: func() *corev1.Secret {
				s := ownedSecret()
				s.Labels = nil
				return s
			}(),
			crt:          crt,
			wantNotFound: true,
		},
		"rejects the Secret named by spec.secretName even when labeled and owned": {
			// spec.secretTemplate.labels can put the next-private-key label on
			// spec.secretName, and --enable-certificate-owner-ref gives it the
			// controller reference. It must never count as a next private key
			// Secret, or the keymanager would delete the served certificate.
			secret: func() *corev1.Secret {
				s := ownedSecret()
				s.Name = "tls-secret"
				return s
			}(),
			crt: func() *cmapi.Certificate {
				c := crt.DeepCopy()
				c.Status.NextPrivateKeySecretName = new("tls-secret")
				return c
			}(),
			wantNotFound: true,
		},
		"rejects a Secret that does not exist": {
			secret:       nil,
			crt:          crt,
			wantNotFound: true,
		},
		"rejects when nextPrivateKeySecretName is unset": {
			secret: ownedSecret(),
			crt: func() *cmapi.Certificate {
				c := crt.DeepCopy()
				c.Status.NextPrivateKeySecretName = nil
				return c
			}(),
			wantNotFound: true,
		},
		"rejects when nextPrivateKeySecretName is empty": {
			secret: ownedSecret(),
			crt: func() *cmapi.Certificate {
				c := crt.DeepCopy()
				c.Status.NextPrivateKeySecretName = new("")
				return c
			}(),
			wantNotFound: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// The factory is never started, so the informer's indexer is what the
			// lister reads. Seed it directly.
			factory := coreinformers.NewSharedInformerFactory(kubefake.NewSimpleClientset(), 0)
			lister := factory.Core().V1().Secrets().Lister()
			if test.secret != nil {
				if err := factory.Core().V1().Secrets().Informer().GetIndexer().Add(test.secret); err != nil {
					t.Fatal(err)
				}
			}

			got, err := GetNextPrivateKeySecret(lister.Secrets("testns"), test.crt)

			if test.wantNotFound {
				if !apierrors.IsNotFound(err) {
					t.Errorf("expected a NotFound error, got err=%v secret=%v", err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil || got.Name != test.wantName {
				t.Errorf("expected Secret %q, got %v", test.wantName, got)
			}
		})
	}
}
