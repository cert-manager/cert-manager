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

package clusterissuers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// TestIssuersForSecret_ACMEDNS01Solver is a regression test for
// https://github.com/cert-manager/cert-manager/issues/9036: a ClusterIssuer
// with an ACME DNS-01 solver referencing a Secret must be requeued when that
// Secret is created or updated, the same way it already is for its
// PrivateKey and ExternalAccountBinding Secrets.
func TestIssuersForSecret_ACMEDNS01Solver(t *testing.T) {
	const clusterResourceNamespace = "cert-manager"

	route53Issuer := gen.ClusterIssuer("route53-issuer",
		gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
			{DNS01: &cmacme.ACMEChallengeSolverDNS01{
				Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
					SecretAccessKey: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: "route53-creds"},
						Key:                  "secret-access-key",
					},
				},
			}},
		}),
	)
	eabIssuer := gen.ClusterIssuer("eab-issuer",
		gen.SetIssuerACMEEAB("kid", "eab-creds"),
	)
	privateKeyIssuer := gen.ClusterIssuer("privatekey-issuer",
		gen.SetIssuerACMEPrivKeyRef("privatekey-creds"),
	)
	caIssuer := gen.ClusterIssuer("ca-issuer",
		gen.SetIssuerCASecretName("ca-creds"),
	)

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, iss := range []*v1.ClusterIssuer{route53Issuer, eabIssuer, privateKeyIssuer, caIssuer} {
		require.NoError(t, indexer.Add(iss))
	}

	c := &controller{
		clusterIssuerLister:      cmlisters.NewClusterIssuerLister(indexer),
		clusterResourceNamespace: clusterResourceNamespace,
	}

	tests := map[string]struct {
		secret        *corev1.Secret
		expectIssuers []string
	}{
		"a Secret referenced by a DNS-01 solver requeues the matching ClusterIssuer": {
			secret:        secretNamed(clusterResourceNamespace, "route53-creds"),
			expectIssuers: []string{"route53-issuer"},
		},
		"a Secret referenced by ExternalAccountBinding still requeues its ClusterIssuer": {
			secret:        secretNamed(clusterResourceNamespace, "eab-creds"),
			expectIssuers: []string{"eab-issuer"},
		},
		"a Secret referenced by the ACME PrivateKey still requeues its ClusterIssuer": {
			secret:        secretNamed(clusterResourceNamespace, "privatekey-creds"),
			expectIssuers: []string{"privatekey-issuer"},
		},
		"a Secret referenced by a CA ClusterIssuer still requeues its ClusterIssuer": {
			secret:        secretNamed(clusterResourceNamespace, "ca-creds"),
			expectIssuers: []string{"ca-issuer"},
		},
		"a same-named Secret outside the cluster resource namespace does not requeue": {
			secret:        secretNamed("some-other-namespace", "route53-creds"),
			expectIssuers: nil,
		},
		"an unreferenced Secret requeues nothing": {
			secret:        secretNamed(clusterResourceNamespace, "unrelated-secret"),
			expectIssuers: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			affected, err := c.issuersForSecret(tc.secret)
			require.NoError(t, err)

			var names []string
			for _, iss := range affected {
				names = append(names, iss.Name)
			}
			assert.Equal(t, tc.expectIssuers, names)
		})
	}
}

func secretNamed(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}
}
