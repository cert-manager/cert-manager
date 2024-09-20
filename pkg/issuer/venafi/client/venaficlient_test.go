/*
Copyright 2020 The cert-manager Authors.

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

	vcert "github.com/Venafi/vcert/v5"
	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

const (
	zone                = "test-zone"
	username            = "test-username"
	password            = "test-password"
	accessToken         = "KT2EEVTIjWM/37L78dqJAg=="
	apiKey              = "test-api-key"
	customKey           = "test-custom-key"
	defaultCaKey        = "ca.crt"
	customCaKey         = "custom-ca-key"
	tppUrl              = "https://tpp.example.com/vedsdk"
	customCaSecretName  = "custom-ca-secret"
	testLeafCertificate = `-----BEGIN CERTIFICATE-----
MIIFFTCCAv2gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwRjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtDRVJUTUFOQUdFUjEUMBIGA1UEAwwLZm9v
LmJhci5pbnQwHhcNMjAxMDAyMTQ1NzMwWhcNMjExMDEyMTQ1NzMwWjBKMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAoMC0NFUlRNQU5BR0VSMRgwFgYD
VQQDDA9leGFtcGxlLmZvby5iYXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC8yTGzYIX3OoRma11vewbNf8dgKHc9GgvJJ29SVjaNwRAJjKOXokGOwcyQ
7Ieb1puYQ5KdSPC1IxyUx77URovIvd3Wql+J1gIxyrdN3om3uQdJ2ck6xatBZ8BI
Y3Z+6WpUQ2067Wk4KpUGfMrbGg5zVcesh6zc8J9yEiItUENeR+6GyEf+B8IJ0xqe
5lps2LaxZp6I6vaKeMELjj17Nb9r81Rjyk8BN7yX74tFE1mUGX9o75tsODU9IrYW
nqSl5gr2PO9Zb/bd6zhoncLJr9kj2tk6cLRPht+JOPoA2LAP6D0aEdC3a2XWuj2E
EsUYJR9e5C/X49VQaak0VdNnhO6RAgMBAAGjggEHMIIBAzAJBgNVHRMEAjAAMBEG
CWCGSAGG+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYkT3BlblNTTCBHZW5lcmF0
ZWQgU2VydmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBQ41U/GiA2rQtuMz6tNL55C
o4pnBDBqBgNVHSMEYzBhgBSfus9cb7UA/PCfHJAGtL6ot2EpLKFFpEMwQTEPMA0G
A1UEAwwGYmFyLmNhMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAoM
C0NFUlRNQU5BR0VSggIQADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDQYJKoZIhvcNAQELBQADggIBAFFTJNqKSkkJNWWt+R7WFNIEKoaPcFH5
yupCQRYX9LK2cXdBQpF458/PFxREyt5jKFUcDyzQhOglFYq0hfcoAc2EB3Vw8Ww9
c4QCiCU6ehJVMRt7MzZ9uUVGCRVOA+Fa1tIFfL3dKlI+4pTSbDhNHRqDtFhfWOZK
bgtruQEUOW1lQR61AsidOF1iwDBU6ckpVY9Lc2SHEAfQFs0MoXmJ8B4MqFptF4+H
al+IAeQ1bC/2EccFYg3tq9+YKHDCyghHf8qeKJR9tZslvkHrAzuX56e0MHxM3AD6
D0L8nG3DsrHcjK0MlVUWmq0QFnY5t+78iocLoQZzpILZYuZn3p+XNlUdW4lcqSBn
y5fUwQ3RIuvN66GBhTeDV4vzYPa7g3i9PoBFoG50Ayr6VtIVn08rnl03lgp57Edv
A5oRrSHcd8Hd8/lk0Y9BpFTnZEg7RLhFhh9nazVp1/pjwaGx449uHIGEoxREQoPq
9Q+KLGMJR2IqiNI6+U1z2j8BChTOPkuAvsnSuAXyotu4BXBL5zbDzfDoggEk1ps1
bfHWnmdelE0WP7h7B0PSA0EXn0pdg2VQIQsknV6y3MCzFQCCSAog/OSguokXG1PG
l6fctDJ3+AF07EjtgArOBkUn7Nt3/CgMN8I1rnBZ1Vmd8yrHEP0E3yRXBL7cDj5j
Fqmd89NQLlGs
-----END CERTIFICATE-----
`
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

func checkTppUrl(t *testing.T, tppUrl string, cnf *vcert.Config) {
	if cnf == nil {
		t.Errorf("expected config but got: %+v", cnf)
	}

	if tppUrl != cnf.BaseUrl {
		t.Errorf("got unexpected BaseUrl set, exp=%s got=%s",
			tppUrl, cnf.BaseUrl)
	}
}

func checkTppCa(t *testing.T, ca string, cnf *vcert.Config) {
	if cnf == nil {
		t.Errorf("expected config but got: %+v", cnf)
	}

	if ca != cnf.ConnectionTrust {
		t.Errorf("got unexpected CA as trust, exp=%s got=%s",
			ca, cnf.ConnectionTrust)
	}
}

func generateSecretLister(s *corev1.Secret, err error) internalinformers.SecretLister {
	return &testlisters.FakeSecretLister{
		SecretsFn: func(string) corelisters.SecretNamespaceLister {
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

	tppIssuerWithoutCA := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			Zone: zone,
			TPP: &cmapi.VenafiTPP{
				URL: tppUrl,
			},
		}),
	)

	tppIssuerWithCABundle := gen.IssuerFrom(tppIssuerWithoutCA,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			TPP: &cmapi.VenafiTPP{
				CABundle: []byte(testLeafCertificate),
			},
		}),
	)

	tppIssuerWithCABundleSecretRef := gen.IssuerFrom(tppIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			TPP: &cmapi.VenafiTPP{
				CABundleSecretRef: &cmmeta.SecretKeySelector{
					Key: customCaKey,
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: customCaSecretName,
					},
				},
			},
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
		"if TPP and neither caBundle nor caBundleSecretRef is specified, CA bundle is not set in vcert config": {
			iss: tppIssuerWithoutCA,
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					tppUsernameKey: []byte(username),
					tppPasswordKey: []byte(password),
				},
			}, nil),
			CheckFn: func(t *testing.T, cnf *vcert.Config) {
				if trust := cnf.ConnectionTrust; trust != "" {
					t.Errorf("got unexpected CA bundle: %s", trust)
				}
				checkTppUrl(t, tppUrl, cnf)
			},
			expectedErr: false,
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
		// NOTE: Below scenarios assume valid TPP CAs, the scenarios with invalid TPP CAs are run part of TestCaBundleForVcertTPP test
		"if TPP and a good caBundle specified, CA bundle should be added to ConnectionTrust and Client in vcert config": {
			iss: tppIssuerWithCABundle,
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					tppAccessTokenKey: []byte(accessToken),
				},
			}, nil),
			CheckFn: func(t *testing.T, cnf *vcert.Config) {
				checkTppCa(t, testLeafCertificate, cnf)
			},
			expectedErr: false,
		},
		"if TPP and a good caBundleSecretRef specified, CA bundle should be added to ConnectionTrust and Client in vcert config": {
			iss: tppIssuerWithCABundleSecretRef,
			// tppAccessTokenKey secret lister is not passed as we only have single secretsLister in testConfigForIssuerT struck
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					customCaKey: []byte(testLeafCertificate),
				},
			}, nil),
			CheckFn: func(t *testing.T, cnf *vcert.Config) {
				checkTppCa(t, testLeafCertificate, cnf)
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

func TestCaBundleForVcertTPP(t *testing.T) {
	baseIssuer := gen.Issuer("non-venafi-issue",
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
	)

	tppIssuer := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			Zone: zone,
			TPP:  &cmapi.VenafiTPP{},
		}),
	)

	tppIssuerWithCABundle := gen.IssuerFrom(tppIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			TPP: &cmapi.VenafiTPP{
				CABundle: []byte(testLeafCertificate),
			},
		}),
	)

	tppIssuerWithCABundleSecretRefNoKey := gen.IssuerFrom(tppIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			TPP: &cmapi.VenafiTPP{
				CABundleSecretRef: &cmmeta.SecretKeySelector{
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: customCaSecretName,
					},
				},
			},
		}),
	)

	tppIssuerWithCABundleSecretRef := gen.IssuerFrom(tppIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			TPP: &cmapi.VenafiTPP{
				CABundleSecretRef: &cmmeta.SecretKeySelector{
					Key: customCaKey,
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: customCaSecretName,
					},
				},
			},
		}),
	)

	tests := map[string]testConfigForIssuerT{
		"if TPP and neither of caBundle nor caBundleSecretRef is specified, CA bundle is not returned": {
			iss:         tppIssuer,
			caBundle:    "",
			expectedErr: false,
		},
		"if TPP and caBundle is specified, correct CA bundle from CABundle should be returned": {
			iss:         tppIssuerWithCABundle,
			caBundle:    testLeafCertificate,
			expectedErr: false,
		},
		"if TPP and caBundleSecretRef is specified, correct CA bundle from CABundleSecretRef should be returned": {
			iss:      tppIssuerWithCABundleSecretRef,
			caBundle: testLeafCertificate,
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					customCaKey: []byte(testLeafCertificate),
				},
			}, nil),
			expectedErr: false,
		},
		"if TPP and caBundleSecretRef is specified without `key`, correct CA bundle from CABundleSecretRef with default key should be returned": {
			iss:      tppIssuerWithCABundleSecretRefNoKey,
			caBundle: testLeafCertificate,
			secretsLister: generateSecretLister(&corev1.Secret{
				Data: map[string][]byte{
					defaultCaKey: []byte(testLeafCertificate),
				},
			}, nil),
			expectedErr: false,
		},
		"if TPP and caBundleSecretRef is specified, but getting secret fails should error": {
			iss:           tppIssuerWithCABundleSecretRef,
			caBundle:      testLeafCertificate,
			secretsLister: generateSecretLister(nil, errors.New("this is a network error")),
			expectedErr:   true,
		},
		// TODO: write test cases where bad CA is passed.
		// above TODO can be ignored if the checks are added to issuer validations per below link
		// https://github.com/cert-manager/cert-manager/blob/v1.14.4/internal/apis/certmanager/validation/issuer.go#L354
		// even though we are not prevalidating, vcert http.Client would anyway fail when using invalid CA
		// 2 scenarios with bad CAs:
		// "if TPP and caBundle is specified, a bad bundle from CABundle should error"
		// "if TPP and caBundleSecretRef is specified, a bad bundle from a CABundleSecretRef should error"
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.runTppCaTest(t)
		})
	}
}

type testConfigForIssuerT struct {
	iss           cmapi.GenericIssuer
	secretsLister internalinformers.SecretLister
	caBundle      string

	expectedErr bool

	CheckFn func(*testing.T, *vcert.Config)
}

func (c *testConfigForIssuerT) runTest(t *testing.T) {
	resp, err := configForIssuer(c.iss, c.secretsLister, "test-namespace", "cert-manager/v0.0.0")
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

func (c *testConfigForIssuerT) runTppCaTest(t *testing.T) {
	caResp, err := caBundleForVcertTPP(c.iss.GetSpec().Venafi.TPP, c.secretsLister, "test-namespace")

	if err != nil && !c.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && c.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	if !c.expectedErr {
		if c.caBundle != string(caResp) {
			t.Errorf("got unexpected CA bundle, exp=%s got=%s",
				c.caBundle, caResp)
		}
	}
}
