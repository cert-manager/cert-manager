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
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testcr "github.com/jetstack/cert-manager/pkg/controller/certificaterequests/test"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	internalvault "github.com/jetstack/cert-manager/pkg/internal/vault"
	fakevault "github.com/jetstack/cert-manager/pkg/internal/vault/fake"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestSign(t *testing.T) {
	rsaPK := testcr.GenerateRSAPrivateKey(t)
	caCSR := testcr.GenerateCSR(t, rsaPK)

	testCR := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestCSR(caCSR),
		gen.SetCertificateRequestIsCA(true),
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
		gen.SetCertificateRequestIssuer(v1alpha1.ObjectReference{
			Name:  "vault-issuer",
			Group: certmanager.GroupName,
			Kind:  "Issuer",
		}),
	)

	_, rsaPEMCert := testcr.GenerateSelfSignedCertFromCR(t, testCR, rsaPK, time.Hour*24*60)

	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gen.DefaultTestNamespace,
			Name:      "token-secret",
		},
		Data: map[string][]byte{
			"my-token-key": []byte("my-secret-token"),
		},
	}

	roleSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gen.DefaultTestNamespace,
			Name:      "role-secret",
		},
		Data: map[string][]byte{
			"my-role-key": []byte("my-secret-role"),
		},
	}

	tests := map[string]testT{
		"if the issuer does not exist then report pending": {
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					`Normal ErrorMissingIssuer Referenced "Issuer" not found: issuer.certmanager.k8s.io "vault-issuer" not found`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},
		"a badly formed CSR should report failure": {
			certificateRequest: gen.CertificateRequestFrom(testCR,
				gen.SetCertificateRequestCSR([]byte("a bad csr")),
			),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{gen.Issuer("vault-issuer")},
				ExpectedEvents: []string{
					`Warning ErrorParsingCSR Failed to decode CSR in spec: error decoding certificate request PEM block: error decoding certificate request PEM block`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},
		"no token or app role secret reference should report pending": {
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{gen.Issuer("vault-issuer",
					gen.SetIssuerVault(v1alpha1.VaultIssuer{}),
				)},
				ExpectedEvents: []string{
					`Normal ErrorVaultInit Failed to initialise vault client for signing: error initializing Vault client tokenSecretRef or appRoleSecretRef not set: error initializing Vault client tokenSecretRef or appRoleSecretRef not set`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},
		"a client with a token secret referenced that doesn't exist should report pending": {
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{gen.Issuer("vault-issuer",
					gen.SetIssuerVault(v1alpha1.VaultIssuer{
						Auth: v1alpha1.VaultAuth{
							TokenSecretRef: v1alpha1.SecretKeySelector{
								Key: "secret-key",
								LocalObjectReference: v1alpha1.LocalObjectReference{
									"non-existing-secret",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{
					`Normal MissingSecret Required resource not found: secret "non-existing-secret" not found: secret "non-existing-secret" not found`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},
		"a client with a app role secret referenced that doesn't exist should report pending": {
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{gen.Issuer("vault-issuer",
					gen.SetIssuerVault(v1alpha1.VaultIssuer{
						Auth: v1alpha1.VaultAuth{
							AppRole: v1alpha1.VaultAppRole{
								RoleId: "my-role-id",
								SecretRef: v1alpha1.SecretKeySelector{
									Key: "secret-key",
									LocalObjectReference: v1alpha1.LocalObjectReference{
										"non-existing-secret",
									},
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{
					`Normal MissingSecret Required resource not found: secret "non-existing-secret" not found: secret "non-existing-secret" not found`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},
		"a client with a token secret referenced with token but failed to sign should report fail": {
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{tokenSecret},
				CertManagerObjects: []runtime.Object{gen.Issuer("vault-issuer",
					gen.SetIssuerVault(v1alpha1.VaultIssuer{
						Auth: v1alpha1.VaultAuth{
							TokenSecretRef: v1alpha1.SecretKeySelector{
								Key: "my-token-key",
								LocalObjectReference: v1alpha1.LocalObjectReference{
									"token-secret",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{
					`Warning ErrorSigning Vault failed to sign certificate: failed to sign: failed to sign`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeVault:   fakevault.NewFakeVault().WithNew(internalvault.New).WithSign(nil, nil, errors.New("failed to sign")),
			expectedErr: false,
		},
		"a client with a app role secret referenced with role but failed to sign should report fail": {
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{roleSecret},
				CertManagerObjects: []runtime.Object{gen.Issuer("vault-issuer",
					gen.SetIssuerVault(v1alpha1.VaultIssuer{
						Auth: v1alpha1.VaultAuth{
							AppRole: v1alpha1.VaultAppRole{
								RoleId: "my-role-id",
								SecretRef: v1alpha1.SecretKeySelector{
									LocalObjectReference: v1alpha1.LocalObjectReference{
										"role-secret",
									},
									Key: "my-role-key",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{
					`Warning ErrorSigning Vault failed to sign certificate: failed to sign: failed to sign`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeVault:   fakevault.NewFakeVault().WithSign(nil, nil, errors.New("failed to sign")),
			expectedErr: false,
		},
		"a client with a token secret referenced with token and signs should return certificate": {
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{tokenSecret},
				CertManagerObjects: []runtime.Object{gen.Issuer("vault-issuer",
					gen.SetIssuerVault(v1alpha1.VaultIssuer{
						Auth: v1alpha1.VaultAuth{
							TokenSecretRef: v1alpha1.SecretKeySelector{
								Key: "my-token-key",
								LocalObjectReference: v1alpha1.LocalObjectReference{
									"token-secret",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{},
				CheckFn:        testcr.NoPrivateKeyFieldsSetCheck(rsaPEMCert),
			},
			fakeVault:   fakevault.NewFakeVault().WithNew(internalvault.New).WithSign(rsaPEMCert, rsaPEMCert, nil),
			expectedErr: false,
		},
		"a client with a app role secret referenced with role should return certificate": {
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{roleSecret},
				CertManagerObjects: []runtime.Object{gen.Issuer("vault-issuer",
					gen.SetIssuerVault(v1alpha1.VaultIssuer{
						Auth: v1alpha1.VaultAuth{
							AppRole: v1alpha1.VaultAppRole{
								RoleId: "my-role-id",
								SecretRef: v1alpha1.SecretKeySelector{
									LocalObjectReference: v1alpha1.LocalObjectReference{
										"role-secret",
									},
									Key: "my-role-key",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{},
				CheckFn:        testcr.NoPrivateKeyFieldsSetCheck(rsaPEMCert),
			},
			fakeVault:   fakevault.NewFakeVault().WithSign(rsaPEMCert, rsaPEMCert, nil),
			expectedErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

type testT struct {
	builder            *testpkg.Builder
	certificateRequest *v1alpha1.CertificateRequest

	expectedErr bool

	fakeVault *fakevault.Vault
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Start()
	defer test.builder.Stop()

	v := NewVault(test.builder.Context)

	if test.fakeVault != nil {
		v.vaultFactory = test.fakeVault.New
	}

	test.builder.Sync()

	resp, err := v.Sign(context.Background(), test.certificateRequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}
	test.builder.CheckAndFinish(resp, err)
}
