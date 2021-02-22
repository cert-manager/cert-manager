/*
Copyright 2021 The cert-manager Authors.

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

package vault

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestImplements(t *testing.T) {
	tests := map[string]struct {
		issuer        cmapi.GenericIssuer
		expImplements bool
	}{
		// Issuer Kind
		"if nil issuer, exp not implements": {
			issuer:        gen.Issuer("test"),
			expImplements: false,
		},
		"if selfsigned issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			expImplements: false,
		},
		"if ca issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerCA(cmapi.CAIssuer{}),
			),
			expImplements: false,
		},
		"if vault issuer, exp implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{}),
			),
			expImplements: true,
		},
		"if venafi issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
			),
			expImplements: false,
		},
		"if acme issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerACME(cmacme.ACMEIssuer{}),
			),
			expImplements: false,
		},

		// ClusterIssuer Kind
		"if nil cluster issuer, exp not implements": {
			issuer:        gen.ClusterIssuer("test"),
			expImplements: false,
		},
		"if selfsigned cluster	issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			expImplements: false,
		},
		"if ca cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerCA(cmapi.CAIssuer{}),
			),
			expImplements: false,
		},
		"if vault cluster issuer, exp implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{}),
			),
			expImplements: true,
		},
		"if venafi cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
			),
			expImplements: false,
		},
		"if acme cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerACME(cmacme.ACMEIssuer{}),
			),
			expImplements: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			i := new(Vault)
			if impl := i.Implements(test.issuer); impl != test.expImplements {
				t.Errorf("unexpected implements, exp=%t got=%t",
					test.expImplements, impl)
			}
		})
	}
}

func TestReferencesSecret(t *testing.T) {
	tests := map[string]struct {
		issuer        cmapi.GenericIssuer
		secret        *corev1.Secret
		expReferences bool
	}{
		// Issuer Kind
		"if issuer not Vault, ignore": {
			issuer: gen.Issuer("test"),
			secret: gen.Secret("secret",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: false,
		},
		"if issuer Vault, but doesn't reference secret, ignore": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: false,
		},
		"if issuer Vault, references same secret in another namespace, ignore": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-token",
				gen.SetSecretNamespace("ns"),
			),
			expReferences: false,
		},
		"if issuer Vault, references same token secret, return true": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-token",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: true,
		},
		"if issuer Vault, references same app role secret, return true": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-app",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: true,
		},
		"if issuer Vault, references same k8s secret, return true": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-k8s",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: true,
		},

		// ClusterIssuer Kind
		"if custer issuer not Vault, ignore": {
			issuer: gen.ClusterIssuer("test"),
			secret: gen.Secret("secret",
				gen.SetSecretNamespace("cert-manager"),
			),
			expReferences: false,
		},
		"if cluster issuer Vault, but doesn't reference secret, ignore": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret",
				gen.SetSecretNamespace("cert-manager"),
			),
			expReferences: false,
		},
		"if cluster issuer Vault, references same secret in another namespace, ignore": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-token",
				gen.SetSecretNamespace("ns"),
			),
			expReferences: false,
		},
		"if cluster issuer Vault, references same token secret, return true": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-token",
				gen.SetSecretNamespace("cert-manager"),
			),
			expReferences: true,
		},
		"if cluster issuer Vault, references same app role secret, return true": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-app",
				gen.SetSecretNamespace("cert-manager"),
			),
			expReferences: true,
		},
		"if cluster issuer Vault, references same k8s secret, return true": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-token",
							},
						},
						AppRole: &cmapi.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-app",
								},
							},
						},
						Kubernetes: &cmapi.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-k8s",
								},
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-k8s",
				gen.SetSecretNamespace("cert-manager"),
			),
			expReferences: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			i := new(Vault)
			i.issuerOptions.ClusterResourceNamespace = "cert-manager"
			if refs := i.ReferencesSecret(test.issuer, test.secret); refs != test.expReferences {
				t.Errorf("unexpected references, exp=%t got=%t",
					test.expReferences, refs)
			}
		})
	}
}
