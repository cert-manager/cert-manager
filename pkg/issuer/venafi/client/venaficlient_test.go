/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package client

import (
	"errors"
	"testing"

	vcert "github.com/Venafi/vcert/v4"
	corev1 "k8s.io/api/core/v1"
	clientcorev1 "k8s.io/client-go/listers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
	testlisters "github.com/jetstack/cert-manager/test/unit/listers"
)

func checkNoConfigReturned(t *testing.T, cnf *vcert.Config) {
	if cnf != nil {
		t.Errorf("expected no config to be returned, got=%+v", cnf)
	}
}

func checkZone(t *testing.T, zone string, cnf *vcert.Config) {
	if cnf == nil {
		t.Errorf("expected config but got: %+v", cnf)
	}

	if zone != cnf.Zone {
		t.Errorf("got unexpected zone set, exp=%s got=%s",
			zone, cnf.Zone)
	}
}

func generateSecretLister(s *corev1.Secret, err error) corelisters.SecretLister {
	return &testlisters.FakeSecretLister{
		SecretsFn: func(string) clientcorev1.SecretNamespaceLister {
			return &testlisters.FakeSecretNamespaceLister{
				GetFn: func(string) (*corev1.Secret, error) {
					return s, err
				},
			}
		},
	}
}

func TestConfigForIssuerT(t *testing.T) {
	zone := "test-zone"
	username := "test-username"
	password := "test-password"
	accessToken := "KT2EEVTIjWM/37L78dqJAg=="
	apiKey := "test-api-key"
	customKey := "test-custom-key"

	baseIssuer := gen.Issuer("non-venafi-issue",
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
	)

	tppIssuer := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			Zone: zone,
			TPP:  &cmapi.VenafiTPP{},
		}),
	)

	cloudIssuer := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			Zone:  zone,
			Cloud: &cmapi.VenafiCloud{},
		}),
	)

	cloudWithKeyIssuer := gen.IssuerFrom(cloudIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			Zone: zone,
			Cloud: &cmapi.VenafiCloud{
				APITokenSecretRef: cmmeta.SecretKeySelector{
					Key: customKey,
				},
			},
		}),
	)

	tests := map[string]testConfigForIssuerT{
		"if Venafi spec has no options in config then should error": {
			iss:         baseIssuer,
			CheckFn:     checkNoConfigReturned,
			expectedErr: true,
		},
		"if TPP but getting secret fails, should error": {
			iss:           tppIssuer,
			secretsLister: generateSecretLister(nil, errors.New("this is a network error")),
			CheckFn:       checkNoConfigReturned,
			expectedErr:   true,
		},
		"if TPP and secret returns user/pass, should return config with those credentials": {
			iss: tppIssuer,
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					tppUsernameKey: []byte(username),
					tppPasswordKey: []byte(password),
				},
			}, nil),
			CheckFn: func(t *testing.T, cnf *vcert.Config) {
				if user := cnf.Credentials.User; user != username {
					t.Errorf("got unexpected username: %s", user)
				}
				if pass := cnf.Credentials.Password; pass != password {
					t.Errorf("got unexpected password: %s", pass)
				}
				checkZone(t, zone, cnf)
			},
			expectedErr: false,
		},
		"if TPP and secret returns access-token, should return config with those credentials": {
			iss: tppIssuer,
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					tppAccessTokenKey: []byte(accessToken),
				},
			}, nil),
			CheckFn: func(t *testing.T, cnf *vcert.Config) {
				if actualAccessToken := cnf.Credentials.AccessToken; actualAccessToken != accessToken {
					t.Errorf("got unexpected accessToken: %q", actualAccessToken)
				}
				checkZone(t, zone, cnf)
			},
			expectedErr: false,
		},
		"if Cloud but getting secret fails, should error": {
			iss:           cloudIssuer,
			secretsLister: generateSecretLister(nil, errors.New("this is a network error")),
			CheckFn:       checkNoConfigReturned,
			expectedErr:   true,
		},
		"if Cloud and secret but no secret key ref, should use API key at default index": {
			iss: cloudIssuer,
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					defaultAPIKeyKey: []byte(apiKey),
				},
			}, nil),
			CheckFn: func(t *testing.T, cnf *vcert.Config) {
				if key := cnf.Credentials.APIKey; key != apiKey {
					t.Errorf("got unexpected API key: %s", key)
				}
				checkZone(t, zone, cnf)
			},
			expectedErr: false,
		},
		"if Cloud and secret with secret key ref, should use API key at default index": {
			iss: cloudWithKeyIssuer,
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					customKey: []byte(apiKey),
				},
			}, nil),
			CheckFn: func(t *testing.T, cnf *vcert.Config) {
				if key := cnf.Credentials.APIKey; key != apiKey {
					t.Errorf("got unexpected API key: %s", key)
				}
				checkZone(t, zone, cnf)
			},
			expectedErr: false,
		},
		"if TPP and Cloud, should chose TPP": {
			iss: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					Zone:  zone,
					TPP:   &cmapi.VenafiTPP{},
					Cloud: &cmapi.VenafiCloud{},
				}),
			),
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					tppUsernameKey: []byte(username),
					tppPasswordKey: []byte(password),
				},
			}, nil),
			CheckFn: func(t *testing.T, cnf *vcert.Config) {
				if user := cnf.Credentials.User; user != username {
					t.Errorf("got unexpected username: %s", user)
				}
				if pass := cnf.Credentials.Password; pass != password {
					t.Errorf("got unexpected password: %s", pass)
				}
				checkZone(t, zone, cnf)
			},
			expectedErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.runTest(t)
		})
	}
}

type testConfigForIssuerT struct {
	iss           cmapi.GenericIssuer
	secretsLister corelisters.SecretLister

	expectedErr bool

	CheckFn func(*testing.T, *vcert.Config)
}

func (c *testConfigForIssuerT) runTest(t *testing.T) {
	resp, err := configForIssuer(c.iss, c.secretsLister, "test-namespace")
	if err != nil && !c.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && c.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	if c.CheckFn != nil {
		c.CheckFn(t, resp)
	}
}
