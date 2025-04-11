/*
Copyright 2024 The cert-manager Authors.

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
	"crypto/rsa"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	internalvault "github.com/cert-manager/cert-manager/internal/vault"
	fakevault "github.com/cert-manager/cert-manager/internal/vault/fake"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	rsaSKFuzz *rsa.PrivateKey
	err       error
)

func init() {
	rsaSKFuzz, err = pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		panic(err)
	}
}

/*
	FuzzVaultCRController is a fuzz test that can be run by way of

go test -fuzz=FuzzVaultCRController. It tests for panics, OOMs
and stackoverflow-related bugs in the Vault reconciliation.
*/
func FuzzVaultCRController(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		secretTokenData,
		customCsrPEM,
		customRsaPEMCert []byte,
		certDuration string,
		addToken,
		addCustomCsrPEM,
		isCA bool,
		baseCRCondition int) {
		tm, err := time.ParseDuration(certDuration)
		if err != nil {
			return
		}

		// Add possibly invalid csrPEM or generate valid
		var csrPEM []byte
		if addCustomCsrPEM {
			csrPEM = customCsrPEM
		} else {
			csrPEM = generateCSR(t, rsaSKFuzz)
		}

		fixedClockStart = time.Now()
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

		baseCRNotApproved := gen.CertificateRequest("test-cr",
			gen.SetCertificateRequestIsCA(isCA),
			gen.SetCertificateRequestCSR(csrPEM),
			gen.SetCertificateRequestDuration(&metav1.Duration{Duration: tm}),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  baseIssuer.Name,
				Group: certmanager.GroupName,
				Kind:  baseIssuer.Kind,
			}),
		)
		var condition cmapi.CertificateRequestConditionType
		switch baseCRCondition % 4 {
		case 0:
			condition = cmapi.CertificateRequestConditionReady
		case 1:
			condition = cmapi.CertificateRequestConditionInvalidRequest
		case 2:
			condition = cmapi.CertificateRequestConditionApproved
		case 3:
			condition = cmapi.CertificateRequestConditionDenied
		}
		baseCR := gen.CertificateRequestFrom(baseCRNotApproved,
			gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
				Type:               condition,
				Status:             cmmeta.ConditionTrue,
				Reason:             "cert-manager.io",
				Message:            "[test-message]",
				LastTransitionTime: &metaFixedClockStart,
			}),
		)

		kubeObjects := []runtime.Object{}
		certManagerObjects := []runtime.Object{}
		certManagerObjects = append(certManagerObjects, baseCR.DeepCopy())

		// Add token if the fuzzer decides to.
		if addToken {
			tokenSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: gen.DefaultTestNamespace,
					Name:      "token-secret",
				},
				Data: map[string][]byte{
					"my-token-key": secretTokenData,
				},
			}
			kubeObjects = append(kubeObjects, tokenSecret)
			certManagerObjects = append(certManagerObjects, gen.IssuerFrom(baseIssuer,
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
			))
		} else {
			certManagerObjects = append(certManagerObjects, baseIssuer.DeepCopy())
		}

		builder := &testpkg.Builder{
			T:                  t,
			KubeObjects:        kubeObjects,
			CertManagerObjects: certManagerObjects,
		}
		builder.Init()
		defer builder.Stop()
		vault := NewVault(builder.Context).(*Vault)

		if !addCustomCsrPEM {
			rsaPEMCert, err := generateSelfSignedCertFromCR(baseCR, rsaSKFuzz)
			if err != nil {
				return
			}

			fakeVault := fakevault.New().WithSign(rsaPEMCert, rsaPEMCert, nil)
			vault.vaultClientBuilder = func(_ context.Context, ns string, _ func(ns string) internalvault.CreateToken, sl internalinformers.SecretLister,
				iss cmapi.GenericIssuer) (internalvault.Interface, error) {
				return fakeVault.New(ns, sl, iss)
			}
		}

		controller := certificaterequests.New(
			apiutil.IssuerVault,
			func(*controllerpkg.Context) certificaterequests.Issuer { return vault },
		)
		if _, _, err := controller.Register(builder.Context); err != nil {
			// Make it explicit if this fails
			panic(err)
		}
		builder.Start()
		_ = controller.Sync(context.Background(), baseCR)
	})
}
