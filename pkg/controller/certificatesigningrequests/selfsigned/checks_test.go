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
	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2/ktesting"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_handleSecretReferenceWorkFunc(t *testing.T) {
	tests := map[string]struct {
		secret          runtime.Object
		existingCSRs    []runtime.Object
		existingIssuers []runtime.Object
		expectedQueue   []types.NamespacedName
	}{
		"if given object is not secret, expect empty queue": {
			secret: gen.Certificate("not-a-secret"),
			existingCSRs: []runtime.Object{
				gen.CertificateSigningRequest("a",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-namespace.a"),
				),
				gen.CertificateSigningRequest("b",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/b"),
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
			secret:       gen.Secret("test-secret", gen.SetSecretNamespace("test-namespace")),
			existingCSRs: []runtime.Object{},
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
			existingCSRs: []runtime.Object{
				gen.CertificateSigningRequest("a",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-namespace.a"),
				),
				gen.CertificateSigningRequest("b",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/b"),
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
				{Name: "a"},
				{Name: "b"},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			builder := &testpkg.Builder{
				T:                  t,
				KubeObjects:        test.existingCSRs,
				CertManagerObjects: test.existingIssuers,
			}
			defer builder.Stop()
			builder.Init()

			lister := builder.Context.KubeSharedInformerFactory.CertificateSigningRequests().Lister()
			helper := issuer.NewHelper(
				builder.Context.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
				builder.Context.SharedInformerFactory.Certmanager().V1().ClusterIssuers().Lister(),
			)

			builder.Start()

			queue := workqueue.NewTypedRateLimitingQueueWithConfig(workqueue.DefaultTypedControllerRateLimiter[types.NamespacedName](), workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{})
			handleSecretReferenceWorkFunc(ktesting.NewLogger(t, ktesting.NewConfig()), lister, helper, queue,
				controllerpkg.IssuerOptions{ClusterResourceNamespace: "test-namespace"},
			)(test.secret)
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
		existingCSRs             []runtime.Object
		existingIssuers          []runtime.Object
		clusterResourceNamespace string
		expectedAffected         []*certificatesv1.CertificateSigningRequest
	}{
		"if no existing requests or issuers, then expect none returned": {
			existingCSRs:             []runtime.Object{},
			existingIssuers:          []runtime.Object{},
			clusterResourceNamespace: "test-namespace",
			expectedAffected:         []*certificatesv1.CertificateSigningRequest{},
		},
		"if no existing requests, then expect none returned": {
			existingCSRs: []runtime.Object{},
			existingIssuers: []runtime.Object{
				gen.Issuer("a",
					gen.SetIssuerNamespace("test-namespace"),
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
				gen.ClusterIssuer("b",
					gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
				),
			},
			clusterResourceNamespace: "test-namespace",
			expectedAffected:         []*certificatesv1.CertificateSigningRequest{},
		},
		"if no existing issuers, then expect none returned": {
			existingCSRs: []runtime.Object{
				gen.CertificateSigningRequest("a",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-namespace.a"),
				),
				gen.CertificateSigningRequest("b",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/b"),
				),
			},
			existingIssuers:          []runtime.Object{},
			clusterResourceNamespace: "test-namespace",
			expectedAffected:         []*certificatesv1.CertificateSigningRequest{},
		},
		"if issuers are not self signed then don't return requests": {
			existingCSRs: []runtime.Object{
				gen.CertificateSigningRequest("a",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-namespace.a"),
				),
				gen.CertificateSigningRequest("b",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/b"),
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
			clusterResourceNamespace: "test-namespace",
			expectedAffected:         []*certificatesv1.CertificateSigningRequest{},
		},
		"should not return requests which are in a different namespace": {
			existingCSRs: []runtime.Object{
				gen.CertificateSigningRequest("a",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/another-namespace.a"),
				),
				gen.CertificateSigningRequest("b",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/b"),
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
			clusterResourceNamespace: "another-namespace",
			expectedAffected:         []*certificatesv1.CertificateSigningRequest{},
		},
		"should sync only requests which match issuers that match namespace of the Secret, ignore secret when cluster resource namespace is different for ClusterIssuers": {
			existingCSRs: []runtime.Object{
				gen.CertificateSigningRequest("a",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-namespace.a"),
				),
				gen.CertificateSigningRequest("b",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/b"),
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
			clusterResourceNamespace: "NOT_test-namespace",
			expectedAffected: []*certificatesv1.CertificateSigningRequest{
				gen.CertificateSigningRequest("a",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-namespace.a"),
				),
			},
		},
		"should return requests that reference a selfsigned issuer and the secret with the private key": {
			existingCSRs: []runtime.Object{
				gen.CertificateSigningRequest("a",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-namespace.a"),
				),
				gen.CertificateSigningRequest("b",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/b"),
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
			clusterResourceNamespace: "test-namespace",
			expectedAffected: []*certificatesv1.CertificateSigningRequest{
				gen.CertificateSigningRequest("a",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-namespace.a"),
				),
				gen.CertificateSigningRequest("b",
					gen.AddCertificateSigningRequestAnnotations(map[string]string{
						"experimental.cert-manager.io/private-key-secret-name": "test-secret",
					}),
					gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/b"),
				),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			builder := &testpkg.Builder{
				T:                  t,
				KubeObjects:        test.existingCSRs,
				CertManagerObjects: test.existingIssuers,
			}
			defer builder.Stop()
			builder.Init()

			lister := builder.Context.KubeSharedInformerFactory.CertificateSigningRequests().Lister()
			helper := issuer.NewHelper(
				builder.Context.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
				builder.Context.SharedInformerFactory.Certmanager().V1().ClusterIssuers().Lister(),
			)

			builder.Start()

			affected, err := certificateSigningRequestsForSecret(ktesting.NewLogger(t, ktesting.NewConfig()), lister, helper, secret.DeepCopy(), controllerpkg.IssuerOptions{
				ClusterResourceNamespace: test.clusterResourceNamespace,
			})

			assert.NoError(t, err)
			assert.ElementsMatch(t, test.expectedAffected, affected)
		})
	}
}
