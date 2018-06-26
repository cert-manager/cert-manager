package issuer

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/util"
	"github.com/jetstack/cert-manager/test/util/vault"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("Vault Issuer", func() {
	f := framework.NewDefaultFramework("create-vault-issuer")

	issuerName := "test-vault-issuer"
	rootMount := "root-ca"
	intermediateMount := "intermediate-ca"
	role := "kubernetes-vault"
	vaultSecretAppRoleName := "vault-role"
	vaultSecretTokenName := "vault-token"
	vaultPath := fmt.Sprintf("%s/sign/%s", intermediateMount, role)
	var roleId, secretId string
	var vaultInit *vault.VaultInitializer

	BeforeEach(func() {
		By("Configuring the Vault server")
		podList, err := f.KubeClientSet.CoreV1().Pods("vault").List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		vaultPodName := podList.Items[0].Name
		vaultInit, err = vault.NewVaultInitializer(vaultPodName, rootMount, intermediateMount, role)
		Expect(err).NotTo(HaveOccurred())
		err = vaultInit.Setup()
		Expect(err).NotTo(HaveOccurred())
		roleId, secretId, err = vaultInit.CreateAppRole()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(vaultSecretAppRoleName, nil)
		vaultInit.CleanAppRole()
		vaultInit.Clean()
	})

	const vaultDefaultDuration = time.Hour * 24 * 90

	vaultURL := "http://vault.vault:8200"
	cases := []struct {
		inputDuration    time.Duration
		inputRenewBefore time.Duration
		waitCondition    v1alpha1.ConditionStatus
		description      string
	}{
		{
			inputDuration:    0,
			inputRenewBefore: 0,
			waitCondition:    v1alpha1.ConditionTrue,
			description:      "should be ready with valid Vault AppRole",
		},
		{
			inputDuration:    time.Hour * 24 * 15,
			inputRenewBefore: 0,
			waitCondition:    v1alpha1.ConditionFalse,
			description:      "should fail when renewBefore is not set and duration is < than 30 days",
		},
		{
			inputDuration:    time.Hour * 24 * 90,
			inputRenewBefore: time.Hour * 24 * 91,
			waitCondition:    v1alpha1.ConditionFalse,
			description:      "should fail when renewBefore is greater than duration",
		},
		{
			inputDuration:    0,
			inputRenewBefore: time.Minute,
			waitCondition:    v1alpha1.ConditionFalse,
			description:      "should fail when renewBefore is shorter than 5 minutes",
		},
	}

	for _, v := range cases {
		v := v
		It(v.description, func() {
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(vault.NewVaultAppRoleSecret(vaultSecretAppRoleName, secretId))
			Expect(err).NotTo(HaveOccurred())

			By("Creating an Issuer")
			_, err = f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerAppRole(issuerName, vaultURL, vaultPath, roleId, vaultSecretAppRoleName, v.inputDuration, v.inputRenewBefore))
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Issuer to become Ready")
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
				issuerName,
				v1alpha1.IssuerCondition{
					Type:   v1alpha1.IssuerConditionReady,
					Status: v.waitCondition,
				})
			Expect(err).NotTo(HaveOccurred())
		})
	}

	It("should fail to init with missing Vault AppRole", func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerAppRole(issuerName, vaultURL, vaultPath, roleId, vaultSecretAppRoleName, 0, 0))
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init with missing Vault Token", func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerToken(issuerName, vaultURL, vaultPath, vaultSecretTokenName, 0, 0))
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})
