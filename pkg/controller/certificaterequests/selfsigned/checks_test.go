/*
Copyright 2022 The cert-manager Authors.

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

package selfsigned

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2/ktesting"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_handleSecretReferenceWorkFunc(t *testing.T) {
	tests := map[string]struct {
		secret          runtime.Object
		existingCRs     []runtime.Object
		existingIssuers []runtime.Object
		expectedQueue   []types.NamespacedName
	}{
		"if given object is not secret, expect empty queue": {
			secret: gen.Certificate("not-a-secret"),
			existingCRs: []runtime.Object{
				gen.CertificateRequest("a",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "a", Kind: "Issuer", Group: "cert-manager.io",
					}),
				),
				gen.CertificateRequest("b",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "b", Kind: "ClusterIssuer", Group: "cert-manager.io",
					}),
				),
			},
			existingIssuers: []runtime.Object{
				gen.Issuer("a",
					gen.SetIssuerNamespace("test-namespace"),
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
				gen.ClusterIssuer("b",
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
			},
			expectedQueue: []types.NamespacedName{},
		},
		"if no requests then expect empty queue": {
			secret:      gen.Secret("test-secret", gen.SetSecretNamespace("test-namespace")),
			existingCRs: []runtime.Object{},
			existingIssuers: []runtime.Object{
				gen.Issuer("a",
					gen.SetIssuerNamespace("test-namespace"),
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
				gen.ClusterIssuer("b",
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
			},
			expectedQueue: []types.NamespacedName{},
		},
		"referenced requests should be added to the queue": {
			secret: gen.Secret("test-secret", gen.SetSecretNamespace("test-namespace")),
			existingCRs: []runtime.Object{
				gen.CertificateRequest("a",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "a", Kind: "Issuer", Group: "cert-manager.io",
					}),
				),
				gen.CertificateRequest("b",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "b", Kind: "ClusterIssuer", Group: "cert-manager.io",
					}),
				),
			},
			existingIssuers: []runtime.Object{
				gen.Issuer("a",
					gen.SetIssuerNamespace("test-namespace"),
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
				gen.ClusterIssuer("b",
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
			},
			expectedQueue: []types.NamespacedName{
				{
					Namespace: "test-namespace",
					Name:      "a",
				},
				{
					Namespace: "test-namespace",
					Name:      "b",
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			builder := &testpkg.Builder{
				T:                  t,
				CertManagerObjects: append(test.existingCRs, test.existingIssuers...),
			}
			defer builder.Stop()
			builder.Init()

			lister := builder.Context.SharedInformerFactory.Certmanager().V1().CertificateRequests().Lister()
			helper := issuer.NewHelper(
				builder.Context.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
				builder.Context.SharedInformerFactory.Certmanager().V1().ClusterIssuers().Lister(),
			)

			builder.Start()

			queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[types.NamespacedName]())
			handleSecretReferenceWorkFunc(ktesting.NewLogger(t, ktesting.NewConfig()), lister, helper, queue)(test.secret)
			require.Equal(t, len(test.expectedQueue), queue.Len())
			var actualQueue []types.NamespacedName
			for range test.expectedQueue {
				i, _ := queue.Get()
				actualQueue = append(actualQueue, i)
			}
			assert.ElementsMatch(t, test.expectedQueue, actualQueue)
		})
	}
}

func Test_certificatesRequestsForSecret(t *testing.T) {
	secret := gen.Secret("test-secret", gen.SetSecretNamespace("test-namespace"))

	tests := map[string]struct {
		existingCRs      []runtime.Object
		existingIssuers  []runtime.Object
		expectedAffected []*cmapi.CertificateRequest
	}{
		"if no existing requests or issuers, then expect none returned": {
			existingCRs:      []runtime.Object{},
			existingIssuers:  []runtime.Object{},
			expectedAffected: []*cmapi.CertificateRequest{},
		},
		"if no existing requests, then expect none returned": {
			existingCRs: []runtime.Object{},
			existingIssuers: []runtime.Object{
				gen.Issuer("a",
					gen.SetIssuerNamespace("test-namespace"),
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
				gen.ClusterIssuer("b",
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
			},
			expectedAffected: []*cmapi.CertificateRequest{},
		},
		"if no existing issuers, then expect none returned": {
			existingCRs: []runtime.Object{
				gen.CertificateRequest("a",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "a", Kind: "Issuer", Group: "cert-manager.io",
					}),
				),
				gen.CertificateRequest("b",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "b", Kind: "ClusterIssuer", Group: "cert-manager.io",
					}),
				),
			},
			existingIssuers:  []runtime.Object{},
			expectedAffected: []*cmapi.CertificateRequest{},
		},
		"if issuers are not self signed then don't return requests": {
			existingCRs: []runtime.Object{
				gen.CertificateRequest("a",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "a", Kind: "Issuer", Group: "cert-manager.io",
					}),
				),
				gen.CertificateRequest("b",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "b", Kind: "ClusterIssuer", Group: "cert-manager.io",
					}),
				),
			},
			existingIssuers: []runtime.Object{
				gen.Issuer("a",
					gen.SetIssuerNamespace("test-namespace"),
					gen.SetIssuerCA(cmapi.CAIssuer{}),
				),
				gen.ClusterIssuer("b",
					gen.SetIssuerCA(cmapi.CAIssuer{}),
				),
			},
			expectedAffected: []*cmapi.CertificateRequest{},
		},
		"if issuer has different group, do nothing": {
			existingCRs: []runtime.Object{
				gen.CertificateRequest("a",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "a", Kind: "Keith", Group: "not-cert-manager.io",
					}),
				),
			},
			existingIssuers:  []runtime.Object{},
			expectedAffected: []*cmapi.CertificateRequest{},
		},
		"should not return requests which are in a different namespace": {
			existingCRs: []runtime.Object{
				gen.CertificateRequest("a",
					gen.SetCertificateRequestNamespace("another-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "a", Kind: "Issuer", Group: "cert-manager.io",
					}),
				),
				gen.CertificateRequest("b",
					gen.SetCertificateRequestNamespace("another-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "b", Kind: "ClusterIssuer", Group: "cert-manager.io",
					}),
				),
			},
			existingIssuers: []runtime.Object{
				gen.Issuer("a",
					gen.SetIssuerNamespace("test-namespace"),
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
				gen.ClusterIssuer("b",
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
			},
			expectedAffected: []*cmapi.CertificateRequest{},
		},
		"should return requests that reference a selfsigned issuer and the secret with the private key": {
			existingCRs: []runtime.Object{
				gen.CertificateRequest("a",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "a", Kind: "Issuer", Group: "cert-manager.io",
					}),
				),
				gen.CertificateRequest("b",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "b", Kind: "ClusterIssuer", Group: "cert-manager.io",
					}),
				),
			},
			existingIssuers: []runtime.Object{
				gen.Issuer("a",
					gen.SetIssuerNamespace("test-namespace"),
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
				gen.ClusterIssuer("b",
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
			},
			expectedAffected: []*cmapi.CertificateRequest{
				gen.CertificateRequest("a",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "a", Kind: "Issuer", Group: "cert-manager.io",
					}),
				),
				gen.CertificateRequest("b",
					gen.SetCertificateRequestNamespace("test-namespace"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						"cert-manager.io/private-key-secret-name": "test-secret",
					}), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name: "b", Kind: "ClusterIssuer", Group: "cert-manager.io",
					}),
				),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			builder := &testpkg.Builder{
				T:                  t,
				CertManagerObjects: append(test.existingCRs, test.existingIssuers...),
			}
			defer builder.Stop()
			builder.Init()

			lister := builder.Context.SharedInformerFactory.Certmanager().V1().CertificateRequests().Lister()
			helper := issuer.NewHelper(
				builder.Context.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
				builder.Context.SharedInformerFactory.Certmanager().V1().ClusterIssuers().Lister(),
			)

			builder.Start()

			affected, err := certificateRequestsForSecret(ktesting.NewLogger(t, ktesting.NewConfig()), lister, helper, secret.DeepCopy())
			assert.NoError(t, err)
			assert.ElementsMatch(t, test.expectedAffected, affected)
		})
	}
}
