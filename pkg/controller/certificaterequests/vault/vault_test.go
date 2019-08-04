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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
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
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

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
		t.Error(err)
		t.FailNow()
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr
}

func TestSign(t *testing.T) {
	rsaSK, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csrPEM := generateCSR(t, rsaSK)

	baseIssuer := gen.Issuer("vault-issuer",
		gen.SetIssuerVault(v1alpha1.VaultIssuer{}),
	)

	testCR := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestIsCA(true),
		gen.SetCertificateRequestCSR(csrPEM),
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
		gen.SetCertificateRequestIssuer(v1alpha1.ObjectReference{
			Name:  baseIssuer.Name,
			Group: certmanager.GroupName,
			Kind:  baseIssuer.Kind,
		}),
	)

	_, rsaPEMCert, err := pki.GenerateSelfSignedCertFromCR(testCR, rsaSK, time.Hour*24*60)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

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
		"no token or app role secret reference should report pending": {
			issuer:             gen.IssuerFrom(baseIssuer),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					`Normal ErrorVaultInit Failed to initialise vault client for signing: error initializing Vault client tokenSecretRef or appRoleSecretRef not set`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: true,
		},
		"a client with a token secret referenced that doesn't exist should report pending": {
			issuer: gen.IssuerFrom(baseIssuer,
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
			),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					`Normal MissingSecret Required secret resource not found: secret "non-existing-secret" not found`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},
		"a client with a app role secret referenced that doesn't exist should report pending": {
			issuer: gen.IssuerFrom(baseIssuer,
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
			),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					`Normal MissingSecret Required secret resource not found: secret "non-existing-secret" not found`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			expectedErr: false,
		},
		"a client with a token secret referenced with token but failed to sign should report fail": {
			issuer: gen.IssuerFrom(baseIssuer,
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
			),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{tokenSecret},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					`Warning ErrorSigning Vault failed to sign certificate: failed to sign`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeVault:   fakevault.NewFakeVault().WithNew(internalvault.New).WithSign(nil, nil, errors.New("failed to sign")),
			expectedErr: false,
		},
		"a client with a app role secret referenced with role but failed to sign should report fail": {
			issuer: gen.IssuerFrom(baseIssuer,
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
			),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{roleSecret},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					`Warning ErrorSigning Vault failed to sign certificate: failed to sign`,
				},
				CheckFn: testcr.MustNoResponse,
			},
			fakeVault:   fakevault.NewFakeVault().WithSign(nil, nil, errors.New("failed to sign")),
			expectedErr: false,
		},
		"a client with a token secret referenced with token and signs should return certificate": {
			issuer: gen.IssuerFrom(baseIssuer,
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
			),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{tokenSecret},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents:     []string{},
				CheckFn:            testcr.NoPrivateKeyFieldsSetCheck(rsaPEMCert),
			},
			fakeVault:   fakevault.NewFakeVault().WithNew(internalvault.New).WithSign(rsaPEMCert, rsaPEMCert, nil),
			expectedErr: false,
		},
		"a client with a app role secret referenced with role should return certificate": {
			issuer: gen.IssuerFrom(baseIssuer,
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
			),
			certificateRequest: testCR,
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{roleSecret},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents:     []string{},
				CheckFn:            testcr.NoPrivateKeyFieldsSetCheck(rsaPEMCert),
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
	issuer             v1alpha1.GenericIssuer

	expectedErr bool

	fakeVault *fakevault.Vault
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Start()
	defer test.builder.Stop()

	v := NewVault(test.builder.Context)

	if test.fakeVault != nil {
		v.vaultClientBuilder = test.fakeVault.New
	}

	test.builder.Sync()

	resp, err := v.Sign(context.Background(), test.certificateRequest, test.issuer)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}
	test.builder.CheckAndFinish(resp, err)
}
