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

package vault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	internalvault "github.com/cert-manager/cert-manager/internal/vault"
	fakevault "github.com/cert-manager/cert-manager/internal/vault/fake"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func generateCSR(t *testing.T, secretKey crypto.Signer) []byte {
	csr, err := gen.CSRWithSigner(secretKey,
		gen.SetCSRCommonName("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func generateSelfSignedCertFromCR(cr *cmapi.CertificateRequest, key crypto.Signer) ([]byte, error) {
	template, err := pki.CertificateTemplateFromCertificateRequest(cr)
	if err != nil {
		return nil, fmt.Errorf("error generating template: %v", err)
	}

	derBytes, err := x509.CreateCertificate(cmrand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("error signing cert: %v", err)
	}

	pemByteBuffer := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemByteBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, fmt.Errorf("failed to encode cert: %v", err)
	}

	return pemByteBuffer.Bytes(), nil
}

func TestSign(t *testing.T) {
	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	baseIssuer := gen.Issuer("vault-issuer",
		gen.SetIssuerVault(cmapi.VaultIssuer{
			Server: "https://example.vault.com",
		}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	rsaSK, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csrPEM := generateCSR(t, rsaSK)

	baseCRNotApproved := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestIsCA(true),
		gen.SetCertificateRequestCSR(csrPEM),
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name:  baseIssuer.Name,
			Group: certmanager.GroupName,
			Kind:  baseIssuer.Kind,
		}),
	)
	baseCRDenied := gen.CertificateRequestFrom(baseCRNotApproved,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionDenied,
			Status:             cmmeta.ConditionTrue,
			Reason:             "Foo",
			Message:            "Certificate request has been denied by cert-manager.io",
			LastTransitionTime: &metaFixedClockStart,
		}),
	)
	baseCR := gen.CertificateRequestFrom(baseCRNotApproved,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionApproved,
			Status:             cmmeta.ConditionTrue,
			Reason:             "cert-manager.io",
			Message:            "Certificate request has been approved by cert-manager.io",
			LastTransitionTime: &metaFixedClockStart,
		}),
	)

	rsaPEMCert, err := generateSelfSignedCertFromCR(baseCR, rsaSK)
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
		"a CertificateRequest without an approved condition should do nothing": {
			certificateRequest: baseCRNotApproved.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCRNotApproved.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal WaitingForApproval Not signing CertificateRequest until it is Approved",
				},
			},
		},
		"a CertificateRequest with a denied condition should update Ready condition with 'Denied'": {
			certificateRequest: baseCRDenied.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCRDenied.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents:     []string{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCRDenied,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Denied",
								Message:            "The CertificateRequest was denied by an approval controller",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"no token, app role secret or kubernetes auth reference should report pending": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal VaultInitError Failed to initialise vault client for signing: error initializing Vault client: tokenSecretRef, appRoleSecretRef, clientCertificate, or Kubernetes auth role not set",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to initialise vault client for signing: error initializing Vault client: tokenSecretRef, appRoleSecretRef, clientCertificate, or Kubernetes auth role not set",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a client with a token secret referenced that doesn't exist should report pending": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(),
					gen.IssuerFrom(baseIssuer, gen.SetIssuerVault(cmapi.VaultIssuer{
						Auth: cmapi.VaultAuth{
							TokenSecretRef: &cmmeta.SecretKeySelector{
								Key: "secret-key",
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "non-existing-secret",
								},
							},
						},
						Server: "https://example.vault.com",
					})),
				},
				ExpectedEvents: []string{
					`Normal SecretMissing Required secret resource not found: secret "non-existing-secret" not found`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Required secret resource not found: secret "non-existing-secret" not found`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a client with a app role secret referenced that doesn't exist should report pending": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), gen.IssuerFrom(baseIssuer,
					gen.SetIssuerVault(cmapi.VaultIssuer{
						Auth: cmapi.VaultAuth{
							AppRole: &cmapi.VaultAppRole{
								RoleId: "my-role-id",
								SecretRef: cmmeta.SecretKeySelector{
									Key: "secret-key",
									LocalObjectReference: cmmeta.LocalObjectReference{
										Name: "non-existing-secret",
									},
								},
							},
						},
						Server: "https://example.vault.com",
					}),
				)},
				ExpectedEvents: []string{
					`Normal SecretMissing Required secret resource not found: secret "non-existing-secret" not found`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Required secret resource not found: secret "non-existing-secret" not found`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"should exit nil and set status pending if referenced issuer is not ready": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(),
					gen.Issuer(baseIssuer.DeepCopy().Name,
						gen.SetIssuerVault(cmapi.VaultIssuer{}),
					)},
				ExpectedEvents: []string{
					"Normal IssuerNotReady Referenced issuer does not have a Ready status condition",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Pending",
								Message:            "Referenced issuer does not have a Ready status condition",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a client with a token secret referenced with token but temporary failed to authenticate should report pending and return error": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{tokenSecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), gen.IssuerFrom(baseIssuer,
					gen.SetIssuerVault(cmapi.VaultIssuer{
						Auth: cmapi.VaultAuth{
							TokenSecretRef: &cmmeta.SecretKeySelector{
								Key: "my-token-key",
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "token-secret",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{
					"Normal VaultInitError Failed to initialise vault client for signing: failed to create vault client, temporary auth failure",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to initialise vault client for signing: failed to create vault client, temporary auth failure",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeVault: fakevault.New().WithNew(func(string, internalinformers.SecretLister, cmapi.GenericIssuer) (*fakevault.Vault, error) {
				return nil, errors.New("failed to create vault client, temporary auth failure")
			}),
			expectedErr: true,
		},
		"a client with a token secret referenced with token but failed to sign should report fail": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{tokenSecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), gen.IssuerFrom(baseIssuer,
					gen.SetIssuerVault(cmapi.VaultIssuer{
						Auth: cmapi.VaultAuth{
							TokenSecretRef: &cmmeta.SecretKeySelector{
								Key: "my-token-key",
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "token-secret",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{
					"Warning SigningError Vault failed to sign certificate: failed to sign",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Vault failed to sign certificate: failed to sign",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeVault: fakevault.New().WithSign(nil, nil, errors.New("failed to sign")),
		},
		"a client with a app role secret referenced with role but failed to sign should report fail": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{roleSecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), gen.IssuerFrom(baseIssuer,
					gen.SetIssuerVault(cmapi.VaultIssuer{
						Auth: cmapi.VaultAuth{
							AppRole: &cmapi.VaultAppRole{
								RoleId: "my-role-id",
								SecretRef: cmmeta.SecretKeySelector{
									LocalObjectReference: cmmeta.LocalObjectReference{
										Name: "role-secret",
									},
									Key: "my-role-key",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{
					`Warning SigningError Vault failed to sign certificate: failed to sign`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Vault failed to sign certificate: failed to sign",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeVault: fakevault.New().WithSign(nil, nil, errors.New("failed to sign")),
		},
		"a client with a token secret referenced with token and signs should return certificate": {
			certificateRequest: baseCR,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{tokenSecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), gen.IssuerFrom(baseIssuer,
					gen.SetIssuerVault(cmapi.VaultIssuer{
						Auth: cmapi.VaultAuth{
							TokenSecretRef: &cmmeta.SecretKeySelector{
								Key: "my-token-key",
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "token-secret",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCertificate(rsaPEMCert),
							gen.SetCertificateRequestCA(rsaPEMCert),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeVault: fakevault.New().WithSign(rsaPEMCert, rsaPEMCert, nil),
		},
		"a client with a app role secret referenced with role should return certificate": {
			certificateRequest: baseCR,
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{tokenSecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), gen.IssuerFrom(baseIssuer,
					gen.SetIssuerVault(cmapi.VaultIssuer{
						Auth: cmapi.VaultAuth{
							AppRole: &cmapi.VaultAppRole{
								RoleId: "my-role-id",
								SecretRef: cmmeta.SecretKeySelector{
									LocalObjectReference: cmmeta.LocalObjectReference{
										Name: "role-secret",
									},
									Key: "my-role-key",
								},
							},
						},
					}),
				)},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCertificate(rsaPEMCert),
							gen.SetCertificateRequestCA(rsaPEMCert),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeVault: fakevault.New().WithSign(rsaPEMCert, rsaPEMCert, nil),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock
			runTest(t, test)
		})
	}
}

type testT struct {
	builder            *testpkg.Builder
	certificateRequest *cmapi.CertificateRequest

	expectedErr bool

	fakeVault *fakevault.Vault
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	vault := NewVault(test.builder.Context).(*Vault)

	if test.fakeVault != nil {
		vault.vaultClientBuilder = func(_ context.Context, ns string, _ func(ns string) internalvault.CreateToken, sl internalinformers.SecretLister,
			iss cmapi.GenericIssuer) (internalvault.Interface, error) {
			return test.fakeVault.New(ns, sl, iss)
		}
	}

	controller := certificaterequests.New(
		apiutil.IssuerVault,
		func(*controllerpkg.Context) certificaterequests.Issuer { return vault },
	)

	if _, _, err := controller.Register(test.builder.Context); err != nil {
		t.Errorf("failed to register context with controller: %v", err)
	}

	test.builder.Start()

	err := controller.Sync(context.Background(), test.certificateRequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}
