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

package certificate

import (
	"context"
	"path"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon"
	vaultaddon "github.com/jetstack/cert-manager/test/e2e/framework/addon/vault"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/jetstack/cert-manager/test/e2e/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var _ = framework.CertManagerDescribe("Vault Issuer Certificate (AppRole with a custom mount path)", func() {
	runVaultCustomAppRoleTests(cmapi.IssuerKind)
})

var _ = framework.CertManagerDescribe("Vault ClusterIssuer Certificate (AppRole with a custom mount path)", func() {
	runVaultCustomAppRoleTests(cmapi.ClusterIssuerKind)
})

func runVaultCustomAppRoleTests(issuerKind string) {
	f := framework.NewDefaultFramework("create-vault-certificate")

	var (
		vault = &vaultaddon.Vault{
			Base: addon.Base,
			Name: "cm-e2e-create-vault-certificate",
		}
	)

	BeforeEach(func() {
		vault.Namespace = f.Namespace.Name
	})

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
			vaultSecretNamespace = f.Config.Addons.CertManager.ClusterResourceNamespace
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
		sec, err := f.KubeClientSet.CoreV1().Secrets(vaultSecretNamespace).Create(context.TODO(), vaultaddon.NewVaultAppRoleSecret(vaultSecretAppRoleName, secretId), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultSecretName = sec.Name
	})

	JustAfterEach(func() {
		By("Cleaning up")
		Expect(vaultInit.Clean()).NotTo(HaveOccurred())

		if issuerKind == cmapi.IssuerKind {
			f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), vaultIssuerName, metav1.DeleteOptions{})
		} else {
			f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(context.TODO(), vaultIssuerName, metav1.DeleteOptions{})
		}

		f.KubeClientSet.CoreV1().Secrets(vaultSecretNamespace).Delete(context.TODO(), vaultSecretName, metav1.DeleteOptions{})
	})

	It("should generate a new valid certificate", func() {
		By("Creating an Issuer")
		vaultURL := vault.Details().Host

		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		var err error
		if issuerKind == cmapi.IssuerKind {
			vaultIssuer := gen.IssuerWithRandomName("test-vault-issuer-",
				gen.SetIssuerNamespace(f.Namespace.Name),
				gen.SetIssuerVaultURL(vaultURL),
				gen.SetIssuerVaultPath(vaultPath),
				gen.SetIssuerVaultCABundle(vault.Details().VaultCA),
				gen.SetIssuerVaultAppRoleAuth("secretkey", vaultSecretName, roleId, authPath))
			iss, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			vaultIssuerName = iss.Name
		} else {
			vaultIssuer := gen.ClusterIssuerWithRandomName("test-vault-issuer-",
				gen.SetIssuerVaultURL(vaultURL),
				gen.SetIssuerVaultPath(vaultPath),
				gen.SetIssuerVaultCABundle(vault.Details().VaultCA),
				gen.SetIssuerVaultAppRoleAuth("secretkey", vaultSecretName, roleId, authPath))
			iss, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			vaultIssuerName = iss.Name
		}

		By("Waiting for Issuer to become Ready")
		if issuerKind == cmapi.IssuerKind {
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
				vaultIssuerName,
				cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmmeta.ConditionTrue,
				})
		} else {
			err = util.WaitForClusterIssuerCondition(f.CertManagerClientSet.CertmanagerV1().ClusterIssuers(),
				vaultIssuerName,
				cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmmeta.ConditionTrue,
				})
		}

		Expect(err).NotTo(HaveOccurred())

		By("Creating a Certificate")
		_, err = certClient.Create(context.TODO(), util.NewCertManagerVaultCertificate(certificateName, certificateSecretName, vaultIssuerName, issuerKind, nil, nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		unsupportedFeatures := featureset.NewFeatureSet(featureset.SaveRootCAToSecret)
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, f.Helper().ValidationSetForUnsupportedFeatureSet(unsupportedFeatures)...)
		Expect(err).NotTo(HaveOccurred())
	})
}
