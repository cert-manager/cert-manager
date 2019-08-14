/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/certutil"
	"github.com/hashicorp/vault/helper/jsonutil"
	corev1 "k8s.io/api/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	vaultfake "github.com/jetstack/cert-manager/pkg/internal/vault/fake"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
	"github.com/jetstack/cert-manager/test/unit/listers"
)

const (
	testCertBundle = `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUAR4qkcRVjl3D2ZNXyAjGrmJJafUwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHZm9vLmJhcjAeFw0xOTA2MTExMTQ4MjZaFw0yOTA2MDgx
MTQ4MjZaMBIxEDAOBgNVBAMMB2Zvby5iYXIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC6nycZ01dEcR1xaMdhP7HWeHEZVTCMBkvk9NJ7CjHBjEcRFPbo
koMfIeuQ2lO+mFXpLo9iJOE+fh+Pl8/vNihS9Xan23EFNYGNukmpup4zcZ5sBueA
sE9A1LwuHxCIhwutvSOatfzbw5i4LrXNncIRabNjHmJgd4j7hhRJF0PR3x5uTV0t
lMsPVtBUX2FehR3ZvJBaYRFk4ITa7wX8a9p2JQeavoeoSxX2UWGxdE9v2oMUU0Sn
+LjzoNHVWzkTZv5yn8X3GKS1Co4bWaeDmZywL8HSkK//ST/rk7UDItWgeetMRvTt
UO1xLjEYU4HO4aPEdmwVha58nzS87pdJm+LfAgMBAAGjUzBRMB0GA1UdDgQWBBR0
B9MwNgun4l7JAyd2tqL24oRmGDAfBgNVHSMEGDAWgBR0B9MwNgun4l7JAyd2tqL2
4oRmGDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAOofYo23Xv
I5fh1sg4cmayLU5TSZ1hv9/qLzqYDu/9MSJtY0ww8RotkZOL5E3sphh8JQfKnj0G
0NvJrq6RP3Bd9FfizF2k1y2Z6D/dorztd5uum6ctdylfBPgeZEemv9aCfdigAwd+
nh5C+XrIPnsN7Xeq3N4gzyLVzdkFHbuMWTqmqJo5XaMEWP3/dzPl447z/QlSXVqe
nCSne2t3DgvoiqS+A1hVLzHeEiwwd9kmQdPUrybwXZ/i6B1sfcxf8eklbiuhtunQ
jy1M5ZaOOfj2WFwmydx1ycGdJbJiKppN3oehi7EJ2lAxwbGoKy4VD4Ks/nMu4TEY
2lUQ3SmEzoFL
-----END CERTIFICATE-----`
)

func generateRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	return pk
}

func generateCSR(t *testing.T, secretKey crypto.Signer) []byte {
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "test",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, secretKey)
	if err != nil {
		t.Errorf("failed to create CSR: %s", err)
		t.FailNow()
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr
}

type testSignT struct {
	issuer     *v1alpha1.Issuer
	fakeLister *listers.FakeSecretLister
	fakeClient *vaultfake.Client

	csrPEM       []byte
	expectedErr  error
	expectedCert string
	expectedCA   string
}

func TestSign(t *testing.T) {
	privatekey := generateRSAPrivateKey(t)
	csrPEM := generateCSR(t, privatekey)

	bundle := certutil.Secret{
		Data: map[string]interface{}{
			"certificate": testCertBundle,
		},
	}

	bundleData, err := jsonutil.EncodeJSON(&bundle)
	if err != nil {
		t.Errorf("failed to encode bundle for testing: %s", err)
		t.FailNow()
	}

	tests := map[string]testSignT{
		"a garbage csr should return err": {
			csrPEM:       []byte("a bad csr"),
			expectedErr:  errors.New("faild to decode CSR for signing: error decoding certificate request PEM block"),
			expectedCert: "",
			expectedCA:   "",
		},

		"a good csr but failed request should error": {
			csrPEM: csrPEM,
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{}),
			),
			fakeClient:   vaultfake.NewFakeClient().WithRawRequest(nil, errors.New("request failed")),
			expectedErr:  errors.New("failed to sign certificate by vault: request failed"),
			expectedCert: "",
			expectedCA:   "",
		},

		"a good csr and good response should return a certificate": {
			csrPEM: csrPEM,
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{}),
			),
			fakeClient: vaultfake.NewFakeClient().WithRawRequest(&vault.Response{
				Response: &http.Response{
					Body: ioutil.NopCloser(bytes.NewReader(bundleData))},
			}, nil),
			expectedErr:  nil,
			expectedCert: testCertBundle,
			expectedCA:   testCertBundle,
		},
	}

	for name, test := range tests {
		v := &Vault{
			namespace:     "test-namespace",
			secretsLister: test.fakeLister,
			issuer:        test.issuer,
			client:        test.fakeClient,
		}

		cert, _, err := v.Sign(test.csrPEM, time.Minute)
		if !reflect.DeepEqual(test.expectedErr, err) {
			t.Errorf("%s: unexpected error, exp=%v got=%v",
				name, test.expectedErr, err)
		}

		if test.expectedCert != string(cert) {
			t.Errorf("unexpected certificate in response bundle, exp=%s got=%s",
				test.expectedCert, cert)
		}
	}
}

type testSetTokenT struct {
	expectedToken string
	expectedErr   error

	issuer     *v1alpha1.Issuer
	fakeLister *listers.FakeSecretLister
	fakeClient *vaultfake.Client
}

func TestSetToken(t *testing.T) {
	tokenSecret := &corev1.Secret{
		Data: map[string][]byte{
			"my-token-key": []byte("my-secret-token"),
		},
	}

	appRoleSecret := &corev1.Secret{
		Data: map[string][]byte{
			"my-role-key": []byte("my-secret-role-token"),
		},
	}

	tests := map[string]testSetTokenT{
		"if neither token secret ref or app role secret ref not found then error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte(testCertBundle),
					Auth:     v1alpha1.VaultAuth{},
				}),
			),
			fakeLister:    listers.FakeSecretListerFrom(listers.NewFakeSecretLister()),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "",
			expectedErr: errors.New(
				"error initializing Vault client tokenSecretRef or appRoleSecretRef not set"),
		},

		"if token secret ref is set but secret doesn't exist should error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte(testCertBundle),
					Auth: v1alpha1.VaultAuth{
						TokenSecretRef: v1alpha1.SecretKeySelector{
							LocalObjectReference: v1alpha1.LocalObjectReference{
								Name: "secret-ref-name",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errors.New("secret does not exists")),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "",
			expectedErr:   errors.New("secret does not exists"),
		},

		"if token secret ref set, return client using token stored": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte(testCertBundle),
					Auth: v1alpha1.VaultAuth{
						TokenSecretRef: v1alpha1.SecretKeySelector{
							LocalObjectReference: v1alpha1.LocalObjectReference{
								Name: "secret-ref-name",
							},
							Key: "my-token-key",
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(tokenSecret, nil),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "my-secret-token",
			expectedErr:   nil,
		},

		"if app role set but secret token not but vault fails to return token, error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte(testCertBundle),
					Auth: v1alpha1.VaultAuth{
						AppRole: v1alpha1.VaultAppRole{
							RoleId: "my-role-id",
							SecretRef: v1alpha1.SecretKeySelector{
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-role-key",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errors.New("secret not found")),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "",
			expectedErr:   errors.New("secret not found"),
		},

		"if app role secret ref set, return client using token stored": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte(testCertBundle),
					Auth: v1alpha1.VaultAuth{
						AppRole: v1alpha1.VaultAppRole{
							RoleId: "my-role-id",
							SecretRef: v1alpha1.SecretKeySelector{
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-role-key",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(appRoleSecret, nil),
			),
			fakeClient: vaultfake.NewFakeClient().WithRawRequest(&vault.Response{
				Response: &http.Response{
					Body: ioutil.NopCloser(
						strings.NewReader(
							`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"warnings":null,"data":{"id":"my-roleapp-token"}}`),
					),
				},
			}, nil),
			expectedToken: "my-roleapp-token",
			expectedErr:   nil,
		},
		"if app role secret ref and token secret set, take preference on token secret": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte(testCertBundle),
					Auth: v1alpha1.VaultAuth{
						AppRole: v1alpha1.VaultAppRole{
							RoleId: "my-role-id",
							SecretRef: v1alpha1.SecretKeySelector{
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-role-key",
							},
						},
						TokenSecretRef: v1alpha1.SecretKeySelector{
							LocalObjectReference: v1alpha1.LocalObjectReference{
								Name: "secret-ref-name",
							},
							Key: "my-token-key",
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(tokenSecret, nil),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "my-secret-token",
			expectedErr:   nil,
		},
	}

	for name, test := range tests {
		v := &Vault{
			namespace:     "test-namespace",
			secretsLister: test.fakeLister,
			issuer:        test.issuer,
		}

		err := v.setToken(test.fakeClient)
		if !reflect.DeepEqual(test.expectedErr, err) {
			t.Errorf("%s: unexpected error, exp=%v got=%v",
				name, test.expectedErr, err)
		}

		if test.fakeClient.Token() != test.expectedToken {
			t.Errorf("%s: got unexpected client token, exp=%s got=%s",
				name, test.expectedToken, test.fakeClient.Token())
		}
	}
}

type testAppRoleRefT struct {
	expectedRoleID   string
	expectedSecretID string
	expectedErr      error

	appRole *v1alpha1.VaultAppRole

	fakeLister *listers.FakeSecretLister
}

func TestAppRoleRef(t *testing.T) {
	errSecretGet := errors.New("no secret found")

	basicAppRoleRef := &v1alpha1.VaultAppRole{
		RoleId: "my-role-id",
	}

	tests := map[string]testAppRoleRefT{
		"failing to get secret should error": {
			appRole: basicAppRoleRef,
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errSecretGet),
			),
			expectedRoleID:   "",
			expectedSecretID: "",
			expectedErr:      errSecretGet,
		},

		"no data in key should fail": {
			appRole: &v1alpha1.VaultAppRole{
				RoleId: "",
				SecretRef: v1alpha1.SecretKeySelector{
					LocalObjectReference: v1alpha1.LocalObjectReference{
						Name: "secret-name",
					},
					Key: "my-key",
				},
			},
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo": []byte("bar"),
						},
					}, nil),
			),
			expectedRoleID:   "",
			expectedSecretID: "",
			expectedErr:      errors.New(`no data for "my-key" in secret 'test-namespace/secret-name'`),
		},

		"should return roleID and secretID with trimmed space": {
			appRole: &v1alpha1.VaultAppRole{
				RoleId: "    my-role-id  ",
				SecretRef: v1alpha1.SecretKeySelector{
					LocalObjectReference: v1alpha1.LocalObjectReference{
						Name: "secret-name",
					},
					Key: "my-key",
				},
			},
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo":    []byte("bar"),
							"my-key": []byte("    my-key-data   "),
						},
					}, nil),
			),
			expectedRoleID:   "my-role-id",
			expectedSecretID: "my-key-data",
			expectedErr:      nil,
		},
	}

	for name, test := range tests {
		v := &Vault{
			namespace:     "test-namespace",
			secretsLister: test.fakeLister,
			issuer:        nil,
		}

		roleID, secretID, err := v.appRoleRef(test.appRole)
		if !reflect.DeepEqual(test.expectedErr, err) {
			t.Errorf("%s: unexpected error, exp=%v got=%v",
				name, test.expectedErr, err)
		}

		if test.expectedRoleID != roleID {
			t.Errorf("%s: got unexpected roleID, exp=%s got=%s",
				name, test.expectedRoleID, roleID)
		}

		if test.expectedSecretID != secretID {
			t.Errorf("%s: got unexpected secretID, exp=%s got=%s",
				name, test.expectedSecretID, secretID)
		}
	}
}

type testTokenRefT struct {
	expectedToken string
	expectedErr   error

	key string

	fakeLister *listers.FakeSecretLister
}

func TestTokenRef(t *testing.T) {
	errSecretGet := errors.New("no secret found")

	testName, testNamespace := "test-name", "test-namespace"

	tests := map[string]testTokenRefT{
		"failing to get secret should error": {
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errSecretGet),
			),
			key:           "a-key",
			expectedToken: "",
			expectedErr:   errSecretGet,
		},

		"if no vault at key exists then error": {
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo": []byte("bar"),
						},
					}, nil),
			),

			key:           "a-key",
			expectedToken: "",
			expectedErr: fmt.Errorf(`no data for "a-key" in secret '%s/%s'`,
				testName, testNamespace),
		},
		"if value exists at key then return with whitespace trimmed": {
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo":   []byte("bar"),
							"a-key": []byte(" my-token              "),
						},
					}, nil),
			),

			key:           "a-key",
			expectedToken: "my-token",
		},
		"if no key is given then it should default to 'token'": {
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo":   []byte("bar"),
							"token": []byte(" my-token              "),
						},
					}, nil),
			),

			key:           "",
			expectedToken: "my-token",
		},
	}

	for name, test := range tests {
		v := &Vault{
			namespace:     "test-namespace",
			secretsLister: test.fakeLister,
			issuer:        nil,
		}

		token, err := v.tokenRef("test-name", "test-namespace", test.key)
		if !reflect.DeepEqual(test.expectedErr, err) {
			t.Errorf("%s: unexpected error, exp=%v got=%v",
				name, test.expectedErr, err)
		}

		if test.expectedToken != token {
			t.Errorf("%s: got unexpected token, exp=%s got=%s",
				name, test.expectedToken, token)
		}
	}
}

type testNewConfigT struct {
	expectedErr error
	issuer      *v1alpha1.Issuer
	checkFunc   func(cfg *vault.Config) error
}

func TestNewConfig(t *testing.T) {
	tests := map[string]testNewConfigT{
		"no CA bundle set in issuer should return nil": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: nil,
				}),
			),
			expectedErr: nil,
		},

		"a bad cert bundle should error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte("a bad cert bundle"),
				}),
			),
			expectedErr: errors.New("error loading Vault CA bundle"),
		},

		"a good cert bundle should be added to the config": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte(testCertBundle),
				}),
			),
			expectedErr: nil,
			checkFunc: func(cfg *vault.Config) error {
				testCA := x509.NewCertPool()
				testCA.AppendCertsFromPEM([]byte(testCertBundle))
				subs := cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs.Subjects()

				err := fmt.Errorf("got unexpected root CAs in config, exp=%s got=%s",
					testCA.Subjects(), subs)
				if len(subs) != len(testCA.Subjects()) {
					return err
				}
				for i := range subs {
					if !bytes.Equal(subs[i], testCA.Subjects()[i]) {
						return err
					}
				}

				return nil
			},
		},
	}

	for name, test := range tests {
		v := &Vault{
			namespace:     "test-namespace",
			secretsLister: nil,
			issuer:        test.issuer,
		}

		cfg, err := v.newConfig()
		if !reflect.DeepEqual(test.expectedErr, err) {
			t.Errorf("%s: unexpected error, exp=%v got=%v",
				name, test.expectedErr, err)
		}

		if test.checkFunc != nil {
			if err := test.checkFunc(cfg); err != nil {
				t.Errorf("%s: check function failed: %s",
					name, err)
			}
		}
	}
}

type requestTokenWithAppRoleRefT struct {
	client  Client
	appRole *v1alpha1.VaultAppRole

	fakeLister *listers.FakeSecretLister

	expectedToken string
	expectedErr   error
}

func TestRequestTokenWithAppRoleRef(t *testing.T) {
	basicAppRoleRef := &v1alpha1.VaultAppRole{
		RoleId: "test-role-id",
		SecretRef: v1alpha1.SecretKeySelector{
			LocalObjectReference: v1alpha1.LocalObjectReference{
				Name: "test-secret",
			},
			Key: "my-key",
		},
	}

	basicSecretLister := listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
		listers.SetFakeSecretNamespaceListerGet(
			&corev1.Secret{
				Data: map[string][]byte{
					"my-key": []byte("my-key-data"),
				},
			}, nil),
	)

	tests := map[string]requestTokenWithAppRoleRefT{
		"a secret reference that does not exist should error": {
			client:  vaultfake.NewFakeClient(),
			appRole: basicAppRoleRef,
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errors.New("secret not found")),
			),

			expectedToken: "",
			expectedErr:   errors.New("secret not found"),
		},
		"if a raw request fails then error": {
			client:     vaultfake.NewFakeClient().WithRawRequest(nil, errors.New("request failed")),
			appRole:    basicAppRoleRef,
			fakeLister: basicSecretLister,

			expectedToken: "",
			expectedErr:   errors.New("error logging in to Vault server: request failed"),
		},
		"no id in the JSON response should return no token": {
			client: vaultfake.NewFakeClient().WithRawRequest(
				&vault.Response{
					Response: &http.Response{
						Body: ioutil.NopCloser(
							strings.NewReader(
								`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"warnings":null,"data":{}}`),
						),
					},
				}, nil,
			),
			appRole:    basicAppRoleRef,
			fakeLister: basicSecretLister,

			expectedToken: "",
			expectedErr:   errors.New("no token returned"),
		},
		"an id in the JSON response should return that token": {
			client: vaultfake.NewFakeClient().WithRawRequest(
				&vault.Response{
					Response: &http.Response{
						Body: ioutil.NopCloser(
							strings.NewReader(
								`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"warnings":null,"data":{"id":"my-token"}}`),
						),
					},
				}, nil,
			),
			appRole:    basicAppRoleRef,
			fakeLister: basicSecretLister,

			expectedToken: "my-token",
			expectedErr:   nil,
		},
		"a client_token present should take president over id": {
			client: vaultfake.NewFakeClient().WithRawRequest(
				&vault.Response{
					Response: &http.Response{
						Body: ioutil.NopCloser(
							strings.NewReader(
								`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"warnings":null,"data":{"id":"my-token"},"auth":{"client_token":"my-client-token"}}`),
						),
					},
				}, nil,
			),
			appRole:    basicAppRoleRef,
			fakeLister: basicSecretLister,

			expectedToken: "my-client-token",
			expectedErr:   nil,
		},
	}

	for name, test := range tests {
		v := &Vault{
			namespace:     "test-namespace",
			secretsLister: test.fakeLister,
			issuer:        nil,
		}

		token, err := v.requestTokenWithAppRoleRef(test.client, test.appRole)
		if !reflect.DeepEqual(test.expectedErr, err) {
			t.Errorf("%s: unexpected error, exp=%v got=%v",
				name, test.expectedErr, err)
		}

		if test.expectedToken != token {
			t.Errorf("%s: got unexpected token, exp=%s got=%s",
				name, test.expectedToken, token)
		}
	}
}
