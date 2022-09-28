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

package certificaterequest

import (
	"context"
	"crypto/x509"
	"net"
	"path"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon"
	vaultaddon "github.com/cert-manager/cert-manager/test/e2e/framework/addon/vault"
	"github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var _ = framework.CertManagerDescribe("Vault Issuer CertificateRequest (AppRole with a custom mount path)", func() {
	runVaultCustomAppRoleTests(cmapi.IssuerKind)
})

var _ = framework.CertManagerDescribe("Vault ClusterIssuer CertificateRequest (AppRole with a custom mount path)", func() {
	runVaultCustomAppRoleTests(cmapi.ClusterIssuerKind)
})

func runVaultCustomAppRoleTests(issuerKind string) {
	f := framework.NewDefaultFramework("create-vault-certificaterequest")
	h := f.Helper()

	var (
		vault = &vaultaddon.Vault{
			Base: addon.Base,
			Name: "cm-e2e-create-vault-certificaterequest",
		}

		crDNSNames    = []string{"dnsName1.co", "dnsName2.ninja"}
		crIPAddresses = []net.IP{
			[]byte{8, 8, 8, 8},
			[]byte{1, 1, 1, 1},
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
	certificateRequestName := "test-vault-certificaterequest"
	vaultSecretAppRoleName := "vault-role-"
	vaultPath := path.Join(intermediateMount, "sign", role)
	var roleId, secretId, vaultSecretName string

	var vaultInit *vaultaddon.VaultInitializer

	var vaultIssuerName, vaultSecretNamespace string

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

		crClient := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name)

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

		By("Creating a CertificateRequest")
		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, vaultIssuerName,
			issuerKind, &metav1.Duration{
				Duration: time.Hour * 24 * 90,
			},
			crDNSNames, crIPAddresses, nil, x509.RSA)
		Expect(err).NotTo(HaveOccurred())
		_, err = crClient.Create(context.TODO(), cr, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Minute*5, key)
		Expect(err).NotTo(HaveOccurred())
	})
}
