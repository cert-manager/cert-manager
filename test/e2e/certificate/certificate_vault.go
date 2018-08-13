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

package certificate

import (
	"path"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/util"
	"github.com/jetstack/cert-manager/test/util/vault"
)

var _ = framework.CertManagerDescribe("Vault Certificate (AppRole)", func() {
	f := framework.NewDefaultFramework("create-vault-certificate")

	rootMount := "root-ca"
	intermediateMount := "intermediate-ca"
	role := "kubernetes-vault"
	issuerName := "test-vault-issuer"
	certificateName := "test-vault-certificate"
	certificateSecretName := "test-vault-certificate"
	vaultSecretAppRoleName := "vault-role"
	vaultPath := path.Join(intermediateMount, "sign", role)
	authPath := "approle"
	var vaultInit *vault.VaultInitializer
	var roleId string
	var secretId string

	BeforeEach(func() {
		By("Configuring the Vault server")
		podList, err := f.KubeClientSet.CoreV1().Pods("vault").List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		vaultPodName := podList.Items[0].Name
		vaultInit, err = vault.NewVaultInitializer(vaultPodName, rootMount, intermediateMount, role, authPath)
		Expect(err).NotTo(HaveOccurred())
		err = vaultInit.Setup()
		Expect(err).NotTo(HaveOccurred())
		roleId, secretId, err = vaultInit.CreateAppRole()
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(vault.NewVaultAppRoleSecret(vaultSecretAppRoleName, secretId))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(vaultSecretAppRoleName, nil)
		vaultInit.CleanAppRole()
		vaultInit.Clean()
	})

	vaultURL := "http://vault.vault:8200"
	It("should generate a new valid certificate", func() {
		By("Creating an Issuer")

		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)
		secretClient := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name)

		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerAppRole(issuerName, vaultURL, vaultPath, roleId, vaultSecretAppRoleName, authPath))
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Creating a Certificate")
		_, err = certClient.Create(util.NewCertManagerVaultCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind))
		Expect(err).NotTo(HaveOccurred())

		err = util.WaitCertificateIssuedValid(certClient, secretClient, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

	})
})

var _ = framework.CertManagerDescribe("Vault Certificate (AppRole with a custom mount path)", func() {
	f := framework.NewDefaultFramework("create-vault-certificate")

	rootMount := "root-ca"
	intermediateMount := "intermediate-ca"
	authPath := "custom/path"
	role := "kubernetes-vault"
	issuerName := "test-vault-issuer"
	certificateName := "test-vault-certificate"
	certificateSecretName := "test-vault-certificate"
	vaultSecretAppRoleName := "vault-role"
	vaultPath := path.Join(intermediateMount, "sign", role)
	var vaultInit *vault.VaultInitializer
	var roleId string
	var secretId string

	BeforeEach(func() {
		By("Configuring the Vault server")
		podList, err := f.KubeClientSet.CoreV1().Pods("vault").List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		vaultPodName := podList.Items[0].Name
		vaultInit, err = vault.NewVaultInitializer(vaultPodName, rootMount, intermediateMount, role, authPath)
		Expect(err).NotTo(HaveOccurred())
		err = vaultInit.Setup()
		Expect(err).NotTo(HaveOccurred())
		roleId, secretId, err = vaultInit.CreateAppRole()
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(vault.NewVaultAppRoleSecret(vaultSecretAppRoleName, secretId))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(vaultSecretAppRoleName, nil)
		vaultInit.CleanAppRole()
		vaultInit.Clean()
	})

	vaultURL := "http://vault.vault:8200"
	It("should generate a new valid certificate", func() {
		By("Creating an Issuer")

		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)
		secretClient := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name)

		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerAppRole(issuerName, vaultURL, vaultPath, roleId, vaultSecretAppRoleName, authPath))
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Creating a Certificate")
		_, err = certClient.Create(util.NewCertManagerVaultCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind))
		Expect(err).NotTo(HaveOccurred())

		err = util.WaitCertificateIssuedValid(certClient, secretClient, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())
	})
})
