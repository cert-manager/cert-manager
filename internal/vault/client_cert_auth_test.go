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

package vault

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/listers"
)

func TestClientCertificateSecretNameAuthPreservesNamespace(t *testing.T) {
	const (
		vaultToken = "cert-auth-token"
		vaultPath  = "my_pki_mount/sign/my-role-name"
	)

	privatekey := generateRSAPrivateKey(t)
	csrPEM := generateCSR(t, privatekey)
	chain := newTestChain(t, privatekey)
	rootBundleData, err := bundlePEM(chain.leafPEM, chain.intermediatePEM, chain.rootPEM)
	require.NoError(t, err)

	tests := map[string]struct {
		vaultNS           string
		mountPath         string
		certName          string
		expectedLoginPath string
	}{
		"with namespace": {
			vaultNS:           "vault-ns-1",
			expectedLoginPath: "/v1/auth/cert/login",
		},
		"nested namespace with custom mount path and role name": {
			vaultNS:           "team-a/sub-ns",
			mountPath:         "/v1/auth/custom-cert",
			certName:          "my-cert-role",
			expectedLoginPath: "/v1/auth/custom-cert/login",
		},
		"without namespace": {
			vaultNS:           "",
			expectedLoginPath: "/v1/auth/cert/login",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var (
				loginCalled       bool
				gotLoginNS        string
				gotLoginNSValues  []string
				gotClientCertCN   string
				gotLoginRoleName  string
				gotSignNS         string
				gotSignNSValues   []string
				gotSignVaultToken string
			)

			mux := http.NewServeMux()
			mux.HandleFunc(tc.expectedLoginPath, func(w http.ResponseWriter, r *http.Request) {
				loginCalled = true
				gotLoginNS = r.Header.Get("X-Vault-Namespace")
				gotLoginNSValues = slices.Clone(r.Header.Values("X-Vault-Namespace"))
				if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
					gotClientCertCN = r.TLS.PeerCertificates[0].Subject.CommonName
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
					gotLoginRoleName = body["name"]
				}
				_, err := fmt.Fprintf(w, `{"auth":{"client_token":%q}}`, vaultToken)
				assert.NoError(t, err)
			})
			mux.HandleFunc(fmt.Sprintf("/v1/%s", vaultPath), func(w http.ResponseWriter, r *http.Request) {
				gotSignNS = r.Header.Get("X-Vault-Namespace")
				gotSignNSValues = slices.Clone(r.Header.Values("X-Vault-Namespace"))
				gotSignVaultToken = r.Header.Get("X-Vault-Token")
				_, err := w.Write(rootBundleData)
				assert.NoError(t, err)
			})

			server := httptest.NewUnstartedServer(mux)
			server.TLS = &tls.Config{
				ClientAuth: tls.RequestClientCert,
				MinVersion: tls.VersionTLS12,
			}
			server.StartTLS()
			defer server.Close()

			caBundlePEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: server.Certificate().Raw,
			})

			secretsLister := listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"tls.crt": []byte(testClientCertificate),
							"tls.key": []byte(testClientCertificatePrivateKey),
						},
					}, nil),
			)

			v, err := New(
				t.Context(),
				"k8s-ns1",
				func(ns string) CreateToken { return nil },
				secretsLister,
				&cmapiv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "k8s-ns1",
					},
					Spec: cmapiv1.IssuerSpec{
						IssuerConfig: cmapiv1.IssuerConfig{
							Vault: &cmapiv1.VaultIssuer{
								Server:    server.URL,
								Path:      vaultPath,
								Namespace: tc.vaultNS,
								CABundle:  caBundlePEM,
								Auth: cmapiv1.VaultAuth{
									ClientCertificate: &cmapiv1.VaultClientCertificateAuth{
										Path:       tc.mountPath,
										Name:       tc.certName,
										SecretName: "client-cert-secret",
									},
								},
							},
						},
					},
				}, false)
			require.NoError(t, err)
			require.True(t, loginCalled, "expected Vault clientCertificate login endpoint to be called")
			assert.Equal(t, "client.bar.ca", gotClientCertCN, "expected client certificate from Secret to be presented during TLS handshake")
			assert.Equal(t, tc.certName, gotLoginRoleName)
			if tc.vaultNS != "" {
				assert.Equal(t, tc.vaultNS, gotLoginNS, "expected X-Vault-Namespace header on clientCertificate login request")
			} else {
				assert.Empty(t, gotLoginNSValues, "unexpected X-Vault-Namespace header when Vault namespace is empty")
			}

			certPEM, caPEM, err := v.Sign(csrPEM, time.Hour)
			require.NoError(t, err)
			require.NotEmpty(t, certPEM)
			require.NotEmpty(t, caPEM)
			assert.Equal(t, vaultToken, gotSignVaultToken)
			if tc.vaultNS != "" {
				assert.Equal(t, tc.vaultNS, gotSignNS)
			} else {
				assert.Empty(t, gotSignNSValues)
			}
		})
	}
}
