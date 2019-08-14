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

package certificaterequest

import (
	"crypto/x509"
	"net"
	"path"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	vaultaddon "github.com/jetstack/cert-manager/test/e2e/framework/addon/vault"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

var _ = framework.CertManagerDescribe("Vault CertificateRequest (AppRole)", func() {
	f := framework.NewDefaultFramework("create-vault-certificaterequest")
	h := f.Helper()

	var (
		tiller = &tiller.Tiller{
			Name:               "tiller-deploy",
			ClusterPermissions: false,
		}
		vault = &vaultaddon.Vault{
			Tiller: tiller,
			Name:   "cm-e2e-create-vault-certificaterequest",
		}

		crDNSNames    = []string{"dnsName1.co", "dnsName2.ninja"}
		crIPAddresses = []net.IP{
			[]byte{8, 8, 8, 8},
			[]byte{1, 1, 1, 1},
		}
	)

	BeforeEach(func() {
		tiller.Namespace = f.Namespace.Name
		vault.Namespace = f.Namespace.Name
	})

	f.RequireAddon(tiller)
	f.RequireAddon(vault)

	rootMount := "root-ca"
	intermediateMount := "intermediate-ca"
	role := "kubernetes-vault"
	issuerName := "test-vault-issuer"
	certificateRequestName := "test-vault-certificaterequest"
	vaultSecretAppRoleName := "vault-role"
	vaultPath := path.Join(intermediateMount, "sign", role)
	authPath := "approle"
	var roleId string
	var secretId string
	var vaultInit *vaultaddon.VaultInitializer

	BeforeEach(func() {
		By("Configuring the Vault server")
		vaultInit = &vaultaddon.VaultInitializer{
			Details:           *vault.Details(),
			RootMount:         rootMount,
			IntermediateMount: intermediateMount,
			Role:              role,
			AuthPath:          authPath,
		}
		err := vaultInit.Init()
		Expect(err).NotTo(HaveOccurred())
		err = vaultInit.Setup()
		Expect(err).NotTo(HaveOccurred())
		roleId, secretId, err = vaultInit.CreateAppRole()
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(vaultaddon.NewVaultAppRoleSecret(vaultSecretAppRoleName, secretId))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(vaultSecretAppRoleName, nil)
	})

	It("should generate a new valid certificate", func() {
		By("Creating an Issuer")
		vaultURL := vault.Details().Host

		crClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerAppRole(issuerName, vaultURL, vaultPath, roleId, vaultSecretAppRoleName, authPath, vault.Details().VaultCA))

		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Creating a CertificateRequest")
		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind,
			&metav1.Duration{
				Duration: time.Hour * 24 * 90,
			},
			crDNSNames, crIPAddresses, nil, x509.RSA)
		Expect(err).NotTo(HaveOccurred())
		_, err = crClient.Create(cr)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the Certificate is valid")
		err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Minute*5, key)
		Expect(err).NotTo(HaveOccurred())
	})

	cases := []struct {
		inputDuration    *metav1.Duration
		expectedDuration time.Duration
		label            string
		event            string
	}{
		{
			inputDuration:    &metav1.Duration{time.Hour * 24 * 35},
			expectedDuration: time.Hour * 24 * 35,
			label:            "valid for 35 days",
		},
		{
			inputDuration:    nil,
			expectedDuration: time.Hour * 24 * 90,
			label:            "valid for the default value (90 days)",
		},
		{
			inputDuration:    &metav1.Duration{time.Hour * 24 * 365},
			expectedDuration: time.Hour * 24 * 90,
			label:            "with Vault configured maximum TTL duration (90 days) when requested duration is greater than TTL",
		},
		{
			inputDuration:    &metav1.Duration{time.Hour * 24 * 240},
			expectedDuration: time.Hour * 24 * 90,
			label:            "with a warning event when renewBefore is bigger than the duration",
		},
	}

	for _, v := range cases {
		v := v
		It("should generate a new certificate "+v.label, func() {
			By("Creating an Issuer")
			_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerAppRole(issuerName, vault.Details().Host, vaultPath, roleId, vaultSecretAppRoleName, authPath, vault.Details().VaultCA))
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Issuer to become Ready")
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
				issuerName,
				v1alpha1.IssuerCondition{
					Type:   v1alpha1.IssuerConditionReady,
					Status: v1alpha1.ConditionTrue,
				})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a CertificateRequest")
			crClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

			cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName,
				v1alpha1.IssuerKind, v.inputDuration, crDNSNames, crIPAddresses, nil, x509.RSA)
			Expect(err).NotTo(HaveOccurred())
			_, err = crClient.Create(cr)
			Expect(err).NotTo(HaveOccurred())

			err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Minute*5, key)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Certificate is valid")
			cr, err = crClient.Get(cr.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			f.CertificateRequestDurationValid(cr, v.expectedDuration+(30*time.Second))
		})
	}
})
