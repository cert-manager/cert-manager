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

package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	corelisters "k8s.io/client-go/listers/core/v1"

	internalapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	internalv1 "github.com/cert-manager/cert-manager/internal/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/internal/apis/certmanager/validation"
	vaultinternal "github.com/cert-manager/cert-manager/internal/vault"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/cert-manager/cert-manager/pkg/controller"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

func TestVault_Setup(t *testing.T) {
	// Create a mock Vault HTTP server.
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" || r.URL.Path == "/v1/auth/kubernetes/login" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth":{"client_token": "5b1a0318-679c-9c45-e5c6-d1b9a9035d49"}}`))
		}
	}))
	defer vaultServer.Close()

	tests := []struct {
		name             string
		givenIssuer      v1.IssuerConfig
		expectCond       string
		expectErr        string
		webhookReject    bool
		mockGetSecret    *corev1.Secret
		mockGetSecretErr error
	}{
		{
			name: "developer mistake: the vault field is empty",
			givenIssuer: v1.IssuerConfig{
				Vault: nil,
			},
			expectCond:    "Ready False: VaultError: Vault config cannot be empty",
			webhookReject: true,
		},
		{
			name: "path is missing",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Server: "https://vault.example.com",
				},
			},
			expectCond:    "Ready False: VaultError: Vault server and path are required fields",
			webhookReject: true,
		},
		{
			name: "server is missing",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path: "pki_int",
				},
			},
			expectCond:    "Ready False: VaultError: Vault server and path are required fields",
			webhookReject: true,
		},
		{
			name: "auth.appRole, auth.kubernetes, and auth.tokenSecretRef are mutually exclusive",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{

					Path:   "pki_int",
					Server: "https://vault.example.com",
					Auth: v1.VaultAuth{
						AppRole: &v1.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "cert-manager",
								},
							},
						},
						Kubernetes: &v1.VaultKubernetesAuth{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "cert-manager",
								},
							},
							Path: "kubernetes",
							Role: "cert-manager",
						},
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
							Key: "token",
						},
					},
				},
			},
			expectCond:    "Ready False: VaultError: Multiple auth methods cannot be set on the same Vault issuer",
			webhookReject: true,
		},
		{
			name: "valid auth.appRole",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: vaultServer.URL,
					Auth: v1.VaultAuth{
						AppRole: &v1.VaultAppRole{
							RoleId: "cert-manager",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "cert-manager",
								},
								Key: "token",
							},
							Path: "approle",
						},
					},
				},
			},
			expectCond: "Ready True: VaultVerified: Vault verified",
		},
		{
			name: "invalid auth.appRole: secretRef.key can be omitted",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: "https://vault.example.com",
					Auth: v1.VaultAuth{
						AppRole: &v1.VaultAppRole{
							RoleId: "cert-manager",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "cert-manager",
								},
							},
							Path: "approle",
						},
					},
				},
			},
			expectCond: "Ready False: VaultError: Vault AppRole auth requires secretRef.key",
		},
		{
			name: "invalid auth.appRole: roleId is missing",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: "https://vault.example.com",
					Auth: v1.VaultAuth{
						AppRole: &v1.VaultAppRole{
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "cert-manager",
								},
							},
						},
					},
				},
			},
			expectCond:    "Ready False: VaultError: Vault AppRole auth requires both roleId and tokenSecretRef.name",
			webhookReject: true,
		},
		{
			name: "invalid auth.appRole: secretRef.name is missing",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: "https://vault.example.com",
					Auth: v1.VaultAuth{
						AppRole: &v1.VaultAppRole{
							RoleId: "cert-manager",
						},
					},
				},
			},
			expectCond:    "Ready False: VaultError: Vault AppRole auth requires both roleId and tokenSecretRef.name",
			webhookReject: true,
		},
		{
			name: "valid auth.kubernetes.secretRef",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: vaultServer.URL,
					Auth: v1.VaultAuth{
						Kubernetes: &v1.VaultKubernetesAuth{
							Role: "cert-manager",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "cert-manager",
								},
								Key: "token",
							},
						},
					},
				},
			},
			expectCond: "Ready True: VaultVerified: Vault verified",
		},
		{
			name: "invalid auth.kubernetes.secretRef: name is missing",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: "https://vault.example.com",
					Auth: v1.VaultAuth{
						Kubernetes: &v1.VaultKubernetesAuth{
							Role: "cert-manager",
						},
					},
				},
			},
			expectCond:    "Ready False: VaultError: Vault Kubernetes auth requires either secretRef.name or serviceAccountRef.name to be set",
			webhookReject: true,
		},
		{
			// The field auth.kubernetes.secretRef.key defaults to 'token' if
			// not set.
			name: "valid auth.kubernetes.secretRef: key can be left empty and defaults to 'token'",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: vaultServer.URL,
					Auth: v1.VaultAuth{
						Kubernetes: &v1.VaultKubernetesAuth{
							Role: "cert-manager",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "cert-manager",
								},
							},
						},
					},
				},
			},
			expectCond: "Ready True: VaultVerified: Vault verified",
		},
		{
			name: "invalid auth.kubernetes: role is missing",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: "https://vault.example.com",
					Auth: v1.VaultAuth{
						Kubernetes: &v1.VaultKubernetesAuth{
							Role: "",
							// We set secretRef.name just for the purpose of
							// testing whether the "role" is properly checked.
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "cert-manager",
								},
							},
						},
					},
				},
			},
			expectCond:    "Ready False: VaultError: Vault Kubernetes auth requires a role to be set",
			webhookReject: true,
		},
		{
			name: "valid auth.kubernetes.serviceAccountRef",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: vaultServer.URL,
					Auth: v1.VaultAuth{
						Kubernetes: &v1.VaultKubernetesAuth{
							Role: "cert-manager",
							ServiceAccountRef: &v1.ServiceAccountRef{
								Name: "cert-manager",
							},
						},
					},
				},
			},
			expectCond: "Ready True: VaultVerified: Vault verified",
		},
		{
			name: "invalid auth.kubernetes: serviceAccountRef and secretRef are both set",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: vaultServer.URL,
					Auth: v1.VaultAuth{
						Kubernetes: &v1.VaultKubernetesAuth{
							Role: "cert-manager",
							ServiceAccountRef: &v1.ServiceAccountRef{
								Name: "cert-manager",
							},
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "cert-manager",
								},
							},
						},
					},
				},
			},
			expectCond:    "Ready False: VaultError: Vault Kubernetes auth cannot be used with both secretRef.name and serviceAccountRef.name",
			webhookReject: true,
		},
		{
			name: "valid auth.tokenSecretRef",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: vaultServer.URL,
					Auth: v1.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
							Key: "token",
						},
					},
				},
			},
			expectCond: "Ready True: VaultVerified: Vault verified",
		},
		{
			// The default value for auth.tokenSecretRef.key is 'token'. This
			// behavior is not documented in the API reference, but we keep it
			// for backward compatibility.
			name: "valid auth.tokenSecretRef: key can be omitted",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: vaultServer.URL,
					Auth: v1.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
							Key: "",
						},
					},
				},
			},
			expectCond: "Ready True: VaultVerified: Vault verified",
		},
		{
			name: "server with invalid url should fail to setup",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: "https:/vault.example.com",
					Auth: v1.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
							Key: "",
						},
					},
				},
			},
			expectErr: "Get \"https:///vault.example.com/v1/sys/health\": http: no Host in request URL",
		},
		{
			name: "server with leading whitespace should fail to parse",
			givenIssuer: v1.IssuerConfig{
				Vault: &v1.VaultIssuer{
					Path:   "pki_int",
					Server: " https://vault.example.com",
					Auth: v1.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
							Key: "",
						},
					},
				},
			},
			expectErr: "error initializing Vault client: parse \" https://vault.example.com\": first path segment in URL cannot contain colon",
		},
	}
	for _, tt := range tests {
		tt := tt // G601: Remove after Go 1.22. https://go.dev/wiki/LoopvarExperiment
		t.Run(tt.name, func(t *testing.T) {
			givenIssuer := &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "test-namespace",
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: tt.givenIssuer,
				},
			}
			cmclient := cmfake.NewSimpleClientset(givenIssuer)

			v := &Vault{
				issuer:            givenIssuer,
				Context:           &controller.Context{CMClient: cmclient},
				resourceNamespace: "test-namespace",
				createTokenFn: func(ns string) vaultinternal.CreateToken {
					return func(ctx context.Context, saName string, req *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error) {
						return &authv1.TokenRequest{Status: authv1.TokenRequestStatus{
							Token: "token",
						}}, nil
					}
				},
				secretsLister: &testlisters.FakeSecretLister{
					SecretsFn: func(namespace string) corelisters.SecretNamespaceLister {
						return &testlisters.FakeSecretNamespaceLister{
							GetFn: func(name string) (ret *corev1.Secret, err error) {
								assert.Equal(t, "cert-manager", name)
								assert.Equal(t, "test-namespace", namespace)
								return &corev1.Secret{
									ObjectMeta: metav1.ObjectMeta{Name: "cert-manager", Namespace: "test-namespace"},
									Data:       map[string][]byte{"token": []byte("root")},
								}, nil
							},
						}
					},
				},
			}

			err := v.Setup(context.Background())
			if tt.expectErr != "" {
				assert.EqualError(t, err, tt.expectErr)
				return
			}
			assert.NoError(t, err)

			// The webhook-side validation of the Vault issuer configuration
			// didn't exist for a long time. The only validation that was done
			// was the controller-side validation (i.e., the validation that we
			// do in setup.go). To prevent the breakage of existing Issuer or
			// ClusterIssuers resources due to the webhook-side validation
			// suddently becoming stricter than the controller-side validation,
			// we perform the webhook validation too and check that it passes.
			converted := internalapi.IssuerConfig{}
			err = internalv1.Convert_v1_IssuerConfig_To_certmanager_IssuerConfig(&tt.givenIssuer, &converted, nil)
			assert.NoError(t, err)
			errlist, _ := validation.ValidateIssuerConfig(&converted, field.NewPath("spec", "vault"))
			if tt.webhookReject {
				assert.Error(t, errlist.ToAggregate())
			} else {
				assert.NoError(t, errlist.ToAggregate())
			}

			if tt.expectCond != "" {
				require.Len(t, givenIssuer.Status.Conditions, 1)
				assert.Equal(t, tt.expectCond, fmt.Sprintf("%s %s: %s: %s", givenIssuer.Status.Conditions[0].Type, givenIssuer.Status.Conditions[0].Status, givenIssuer.Status.Conditions[0].Reason, givenIssuer.Status.Conditions[0].Message))
			} else {
				require.Len(t, givenIssuer.Status.Conditions, 0)
			}
		})
	}
}
