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

package certificate

import (
	"path"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	vaultaddon "github.com/jetstack/cert-manager/test/e2e/framework/addon/vault"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

var _ = framework.CertManagerDescribe("Vault Issuer Certificate (AppRole with a custom mount path)", func() {
	runVaultCustomAppRoleTests(cmapi.IssuerKind)
})

var _ = framework.CertManagerDescribe("Vault ClusterIssuer Certificate (AppRole with a custom mount path)", func() {
	runVaultCustomAppRoleTests(cmapi.ClusterIssuerKind)
})

func runVaultCustomAppRoleTests(issuerKind string) {
	f := framework.NewDefaultFramework("create-vault-certificate")
	h := f.Helper()

	var (
		tiller = &tiller.Tiller{
			Name:               "tiller-deploy",
			ClusterPermissions: false,
		}
		vault = &vaultaddon.Vault{
			Tiller: tiller,
			Name:   "cm-e2e-create-vault-certificate",
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
	authPath := "custom/path"
	role := "kubernetes-vault"
	certificateName := "test-vault-certificate"
	certificateSecretName := "test-vault-certificate"
	vaultSecretAppRoleName := "vault-role"
	vaultPath := path.Join(intermediateMount, "sign", role)
	var roleId, secretId, vaultSecretName string
	var vaultIssuerName, vaultSecretNamespace string

	var vaultInit *vaultaddon.VaultInitializer

	BeforeEach(func() {
		By("Configuring the Vault server")
		if issuerKind == cmapi.IssuerKind {
			vaultSecretNamespace = f.Namespace.Name
		} else {
			vaultSecretNamespace = addon.CertManager.Namespace
		}

		vaultInit = &vaultaddon.VaultInitializer{
			Details:           *vault.Details(),
			RootMount:         rootMount,
			IntermediateMount: intermediateMount,
			Role:              role,
			AppRoleAuthPath:   authPath,
		}
		err := vaultInit.Init()
		Expect(err).NotTo(HaveOccurred())
		err = vaultInit.Setup()
		Expect(err).NotTo(HaveOccurred())
		roleId, secretId, err = vaultInit.CreateAppRole()
		Expect(err).NotTo(HaveOccurred())
		sec, err := f.KubeClientSet.CoreV1().Secrets(vaultSecretNamespace).Create(vaultaddon.NewVaultAppRoleSecret(vaultSecretAppRoleName, secretId))
		Expect(err).NotTo(HaveOccurred())

		vaultSecretName = sec.Name
	})

	JustAfterEach(func() {
		By("Cleaning up")
		Expect(vaultInit.Clean()).NotTo(HaveOccurred())

		if issuerKind == cmapi.IssuerKind {
			f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name).Delete(vaultIssuerName, nil)
		} else {
			f.CertManagerClientSet.CertmanagerV1alpha2().ClusterIssuers().Delete(vaultIssuerName, nil)
		}

		f.KubeClientSet.CoreV1().Secrets(vaultSecretNamespace).Delete(vaultSecretName, nil)
	})

	It("should generate a new valid certificate", func() {
		By("Creating an Issuer")
		vaultURL := vault.Details().Host

		certClient := f.CertManagerClientSet.CertmanagerV1alpha2().Certificates(f.Namespace.Name)

		var err error
		if issuerKind == cmapi.IssuerKind {
			iss, err := f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerAppRole("test-vault-issuer-", vaultURL, vaultPath, roleId, vaultSecretName, authPath, vault.Details().VaultCA))
			Expect(err).NotTo(HaveOccurred())

			vaultIssuerName = iss.Name
		} else {
			iss, err := f.CertManagerClientSet.CertmanagerV1alpha2().ClusterIssuers().Create(util.NewCertManagerVaultClusterIssuerAppRole("test-vault-issuer-", vaultURL, vaultPath, roleId, vaultSecretName, authPath, vault.Details().VaultCA))
			Expect(err).NotTo(HaveOccurred())

			vaultIssuerName = iss.Name
		}

		By("Waiting for Issuer to become Ready")
		if issuerKind == cmapi.IssuerKind {
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name),
				vaultIssuerName,
				cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmmeta.ConditionTrue,
				})
		} else {
			err = util.WaitForClusterIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha2().ClusterIssuers(),
				vaultIssuerName,
				cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmmeta.ConditionTrue,
				})
		}

		Expect(err).NotTo(HaveOccurred())

		By("Creating a Certificate")
		_, err = certClient.Create(util.NewCertManagerVaultCertificate(certificateName, certificateSecretName, vaultIssuerName, issuerKind, nil, nil))
		Expect(err).NotTo(HaveOccurred())

		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())
	})
}
