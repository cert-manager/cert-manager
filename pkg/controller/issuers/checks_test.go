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

package issuers

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
// https://github.com/cert-manager/cert-manager/issues/9036: an Issuer with an
// ACME DNS-01 solver referencing a Secret must be requeued when that Secret
// is created or updated, the same way it already is for its PrivateKey and
// ExternalAccountBinding Secrets.
func TestIssuersForSecret_ACMEDNS01Solver(t *testing.T) {
	const ns = "testns"

	route53Issuer := gen.Issuer("route53-issuer",
		gen.SetIssuerNamespace(ns),
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
	eabIssuer := gen.Issuer("eab-issuer",
		gen.SetIssuerNamespace(ns),
		gen.SetIssuerACMEEAB("kid", "eab-creds"),
	)
	privateKeyIssuer := gen.Issuer("privatekey-issuer",
		gen.SetIssuerNamespace(ns),
		gen.SetIssuerACMEPrivKeyRef("privatekey-creds"),
	)
	caIssuer := gen.Issuer("ca-issuer",
		gen.SetIssuerNamespace(ns),
		gen.SetIssuerCASecretName("ca-creds"),
	)
	otherNamespaceIssuer := gen.Issuer("other-ns-issuer",
		gen.SetIssuerNamespace("other"),
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

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, iss := range []*v1.Issuer{route53Issuer, eabIssuer, privateKeyIssuer, caIssuer, otherNamespaceIssuer} {
		require.NoError(t, indexer.Add(iss))
	}

	c := &controller{issuerLister: cmlisters.NewIssuerLister(indexer)}

	tests := map[string]struct {
		secret        *corev1.Secret
		expectIssuers []string
	}{
		"a Secret referenced by a DNS-01 solver requeues the matching Issuer": {
			secret:        secretNamed(ns, "route53-creds"),
			expectIssuers: []string{"route53-issuer"},
		},
		"a Secret referenced by ExternalAccountBinding still requeues its Issuer": {
			secret:        secretNamed(ns, "eab-creds"),
			expectIssuers: []string{"eab-issuer"},
		},
		"a Secret referenced by the ACME PrivateKey still requeues its Issuer": {
			secret:        secretNamed(ns, "privatekey-creds"),
			expectIssuers: []string{"privatekey-issuer"},
		},
		"a Secret referenced by a CA Issuer still requeues its Issuer": {
			secret:        secretNamed(ns, "ca-creds"),
			expectIssuers: []string{"ca-issuer"},
		},
		"a same-named Secret in a different namespace does not requeue": {
			secret:        secretNamed("other", "route53-creds"),
			expectIssuers: []string{"other-ns-issuer"},
		},
		"an unreferenced Secret requeues nothing": {
			secret:        secretNamed(ns, "unrelated-secret"),
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
