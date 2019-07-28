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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	vault "github.com/hashicorp/vault/api"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testfake "github.com/jetstack/cert-manager/pkg/controller/test/fake"
	"github.com/jetstack/cert-manager/test/unit/gen"
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

type testAppRoleRefT struct {
	expectedRoleID   string
	expectedSecretID string
	expectedErr      error

	appRole            *v1alpha1.VaultAppRole
	certificaterequest *v1alpha1.CertificateRequest

	fakeLister *testfake.FakeSecretLister
}

func TestAppRoleRef(t *testing.T) {
	errSecretGet := errors.New("no secret found")

	basicAppRoleRef := &v1alpha1.VaultAppRole{
		RoleId: "my-role-id",
	}

	tests := map[string]testAppRoleRefT{
		"failing to get secret should error": {
			appRole: basicAppRoleRef,
			certificaterequest: gen.CertificateRequest("test",
				gen.SetCertificateRequestNamespace("test-namespace"),
			),
			fakeLister: gen.FakeSecretListerFrom(testfake.NewFakeSecretLister(),
				gen.SetFakeSecretNamespaceListerGet(nil, errSecretGet),
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
			certificaterequest: gen.CertificateRequest("test",
				gen.SetCertificateRequestNamespace("test-namespace"),
			),
			fakeLister: gen.FakeSecretListerFrom(testfake.NewFakeSecretLister(),
				gen.SetFakeSecretNamespaceListerGet(
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
			certificaterequest: gen.CertificateRequest("test",
				gen.SetCertificateRequestNamespace("test-namespace"),
			),
			fakeLister: gen.FakeSecretListerFrom(testfake.NewFakeSecretLister(),
				gen.SetFakeSecretNamespaceListerGet(
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
			secretsLister: test.fakeLister,
		}

		roleID, secretID, err := v.appRoleRef(test.certificaterequest, test.appRole)
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

	fakeLister *testfake.FakeSecretLister
}

func TestTokenRef(t *testing.T) {
	errSecretGet := errors.New("no secret found")

	testName, testNamespace := "test-name", "test-namespace"

	tests := map[string]testTokenRefT{
		"failing to get secret should error": {
			fakeLister: gen.FakeSecretListerFrom(testfake.NewFakeSecretLister(),
				gen.SetFakeSecretNamespaceListerGet(nil, errSecretGet),
			),
			key:           "a-key",
			expectedToken: "",
			expectedErr:   errSecretGet,
		},

		"if no vault at key exists then error": {
			fakeLister: gen.FakeSecretListerFrom(testfake.NewFakeSecretLister(),
				gen.SetFakeSecretNamespaceListerGet(
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
			fakeLister: gen.FakeSecretListerFrom(testfake.NewFakeSecretLister(),
				gen.SetFakeSecretNamespaceListerGet(
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
			fakeLister: gen.FakeSecretListerFrom(testfake.NewFakeSecretLister(),
				gen.SetFakeSecretNamespaceListerGet(
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
			secretsLister: test.fakeLister,
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

type testConfigureCertPoolT struct {
	expectedErr error
	issuer      *v1alpha1.Issuer
	checkFunc   func(cfg *vault.Config) error
}

func TestConfigureCertPool(t *testing.T) {

	tests := map[string]testConfigureCertPoolT{
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
		v := new(Vault)
		httpClient := http.DefaultClient
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{},
		}

		cfg := vault.Config{
			HttpClient: http.DefaultClient,
		}

		err := v.configureCertPool(&cfg, test.issuer)
		if !reflect.DeepEqual(test.expectedErr, err) {
			t.Errorf("%s: unexpected error, exp=%v got=%v",
				name, test.expectedErr, err)
		}

		if test.checkFunc != nil {
			if err := test.checkFunc(&cfg); err != nil {
				t.Errorf("%s: check function failed: %s",
					name, err)
			}
		}
	}
}

type testInitVaultClientT struct {
	expectedErr        error
	certificaterequest *v1alpha1.CertificateRequest
	issuer             v1alpha1.GenericIssuer
}

func TestInitVaultClient(t *testing.T) {
	tests := map[string]testInitVaultClientT{
		"a issuer with a bad CA cert should error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte("bad cert"),
				}),
			),
			expectedErr: errors.New("error loading Vault CA bundle"),
		},
		"a vault issuer with no token or role secret reference should error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(v1alpha1.VaultIssuer{
					CABundle: []byte(testCertBundle),
				}),
			),
			expectedErr: errors.New("error initializing Vault client. tokenSecretRef or appRoleSecretRef not set"),
		},

		//TODO:
		// - test for when tokenRef.Name != ""
		// - test for when appRole.RoleId != ""
		// - test for when appRole.RoleId != "" and tokenRef.Name != ""

		//"foo": {
		//	issuer: gen.Issuer("vault-issuer",
		//		gen.SetIssuerVault(v1alpha1.VaultIssuer{
		//			CABundle: []byte(testCertBundle),
		//			Auth: v1alpha1.VaultAuth{
		//				AppRole: v1alpha1.VaultAppRole{
		//					RoleId: "my-role-id",
		//				},
		//			},
		//		}),
		//	),
		//	expectedErr: nil,
		//},
	}

	for name, test := range tests {
		v := new(Vault)

		_, err := v.initVaultClient(test.certificaterequest, test.issuer)
		if !reflect.DeepEqual(test.expectedErr, err) {
			t.Errorf("%s: unexpected error, exp=%v got=%v",
				name, test.expectedErr, err)
		}
	}
}

type requestTokenWithAppRoleRefT struct {
	client  *vault.Client
	appRole *v1alpha1.VaultAppRole

	certificaterequest *v1alpha1.CertificateRequest
	fakeLister         *testfake.FakeSecretLister

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
			Key: "test-key",
		},
	}

	tests := map[string]requestTokenWithAppRoleRefT{
		"a secret reference that does not exist should error": {
			client:  nil,
			appRole: basicAppRoleRef,
			certificaterequest: gen.CertificateRequest("test",
				gen.SetCertificateRequestNamespace("test-namespace"),
			),
			fakeLister: gen.FakeSecretListerFrom(testfake.NewFakeSecretLister(),
				gen.SetFakeSecretNamespaceListerGet(nil, errors.New("secret not found")),
			),

			expectedToken: "",
			expectedErr:   errors.New("error reading Vault AppRole from secret: test-namespace/test-secret: secret not found"),
		},
	}

	for name, test := range tests {
		v := &Vault{
			secretsLister: test.fakeLister,
		}

		token, err := v.requestTokenWithAppRoleRef(test.certificaterequest, test.client, test.appRole)
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
