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
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon"
	vaultaddon "github.com/cert-manager/cert-manager/e2e-tests/framework/addon/vault"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CertManagerDescribe("Vault Issuer", func() {
	f := framework.NewDefaultFramework("create-vault-issuer")
	ctx := context.TODO()

	issuerGeneratorName := "test-vault-issuer-"
	var issuerName string
	vaultSecretServiceAccount := "vault-serviceaccount"
	var roleId, secretId, vaultSecretName string

	appRoleSecretGeneratorName := "vault-approle-secret-"
	var setup *vaultaddon.VaultInitializer

	BeforeEach(func() {
		By("Configuring the Vault server")

		setup = vaultaddon.NewVaultInitializerAllAuth(
			addon.Base.Details().KubeClient,
			*addon.Vault.Details(),
			false,
			"https://kubernetes.default.svc.cluster.local",
		)
		Expect(setup.Init(ctx)).NotTo(HaveOccurred(), "failed to init vault")
		Expect(setup.Setup(ctx)).NotTo(HaveOccurred(), "failed to setup vault")

		var err error
		roleId, secretId, err = setup.CreateAppRole(ctx)
		Expect(err).NotTo(HaveOccurred())

		issuerName = ""
		vaultSecretName = ""

		By("creating a service account for Vault authentication")
		err = setup.CreateKubernetesRole(ctx, f.KubeClientSet, f.Namespace.Name, vaultSecretServiceAccount)
		Expect(err).NotTo(HaveOccurred())
	})

	JustAfterEach(func() {
		By("Cleaning up AppRole")
		if issuerName != "" { // When we test validation errors, the issuer won't be created
			err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuerName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		if vaultSecretName != "" {
			err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), vaultSecretName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		err := setup.CleanAppRole(ctx)
		Expect(err).NotTo(HaveOccurred())

		By("Cleaning up Kubernetes")
		err = setup.CleanKubernetesRole(ctx, f.KubeClientSet, f.Namespace.Name, vaultSecretServiceAccount)
		Expect(err).NotTo(HaveOccurred())

		By("Cleaning up Vault")
		Expect(setup.Clean(ctx)).NotTo(HaveOccurred())
	})

	It("should be ready with a valid AppRole", func() {
		sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), vaultaddon.NewVaultAppRoleSecret(appRoleSecretGeneratorName, secretId), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultSecretName = sec.Name

		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(addon.Vault.Details().VaultCA),
			gen.SetIssuerVaultAppRoleAuth("secretkey", vaultSecretName, roleId, setup.AppRoleAuthPath()))
		vaultIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuerName = vaultIssuer.Name

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init with missing Vault AppRole", func() {
		By("Creating an Issuer")
		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(addon.Vault.Details().VaultCA),
			gen.SetIssuerVaultAppRoleAuth("secretkey", roleId, setup.Role(), setup.AppRoleAuthPath()))
		vaultIssuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuerName = vaultIssuer.Name

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init with missing Vault Token", func() {
		By("Creating an Issuer")
		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(addon.Vault.Details().VaultCA),
			gen.SetIssuerVaultTokenAuth("secretkey", "vault-token"))
		vaultIssuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuerName = vaultIssuer.Name

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be ready with a valid Kubernetes Role and ServiceAccount Secret", func() {
		saTokenSecretName := "vault-sa-secret-" + rand.String(5)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), vaultaddon.NewVaultKubernetesSecret(saTokenSecretName, vaultSecretServiceAccount), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(addon.Vault.Details().VaultCA),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		vaultIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuerName = vaultIssuer.Name

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init with missing Kubernetes Role", func() {
		saTokenSecretName := "vault-sa-secret-" + rand.String(5)
		// we test without creating the secret

		By("Creating an Issuer")
		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(addon.Vault.Details().VaultCA),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		vaultIssuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuerName = vaultIssuer.Name

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init when both caBundle and caBundleSecretRef are set", func() {
		By("Creating an Issuer")
		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(addon.Vault.Details().VaultCA),
			gen.SetIssuerVaultCABundleSecretRef("ca-bundle", f.Namespace.Name, "ca.crt"))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).To(HaveOccurred())

		Expect(err.Error()).To(ContainSubstring(
			"spec.vault.caBundle: Invalid value: \"<snip>\": specified caBundle and caBundleSecretRef cannot be used together",
		))
		Expect(err.Error()).To(ContainSubstring("spec.vault.caBundleSecretRef: Invalid value: \"ca-bundle\": specified caBundleSecretRef and caBundle cannot be used together"))
	})

	It("should be ready with a caBundle from a Kubernetes Secret", func() {
		saTokenSecretName := "vault-sa-secret-" + rand.String(5)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), vaultaddon.NewVaultKubernetesSecret(saTokenSecretName, vaultSecretServiceAccount), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ca-bundle",
			},
			Type: "Opaque",
			Data: map[string][]byte{
				"ca.crt": addon.Vault.Details().VaultCA,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundleSecretRef("ca-bundle", f.Namespace.Name, "ca.crt"),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		vaultIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuerName = vaultIssuer.Name

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be eventually ready when the CA bundle secret gets created after the Issuer", func() {
		saTokenSecretName := "vault-sa-secret-" + rand.String(5)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), vaultaddon.NewVaultKubernetesSecret(saTokenSecretName, vaultSecretServiceAccount), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundleSecretRef("ca-bundle", f.Namespace.Name, "ca.crt"),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		vaultIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuerName = vaultIssuer.Name

		By("Validate that the Issuer is not ready yet")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())

		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ca-bundle",
			},
			Type: "Opaque",
			Data: map[string][]byte{
				"ca.crt": addon.Vault.Details().VaultCA,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("it should become not ready when the CA certificate in the secret changes and doesn't match Vault's CA anymore", func() {
		saTokenSecretName := "vault-sa-secret-" + rand.String(5)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), vaultaddon.NewVaultKubernetesSecret(saTokenSecretName, vaultSecretServiceAccount), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ca-bundle",
			},
			Type: "Opaque",
			Data: map[string][]byte{
				"ca.crt": addon.Vault.Details().VaultCA,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundleSecretRef("ca-bundle", f.Namespace.Name, "ca.crt"),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		vaultIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuerName = vaultIssuer.Name

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Updating CA bundle")
		public, _, err := vaultaddon.GenerateCA()
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ca-bundle",
			},
			Data: map[string][]byte{
				"ca.crt": public,
			},
		}, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Validate that the issuer isn't ready anymore due to Vault still using the old certificate")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})
	It("should be ready with a valid serviceAccountRef", func() {
		// Note that we reuse the same service account as for the Kubernetes
		// auth based on secretRef. There should be no problem doing so.
		By("Creating the Role and RoleBinding to let cert-manager use TokenRequest for the ServiceAccount")
		err := vaultaddon.CreateKubernetesRoleForServiceAccountRefAuth(ctx, f.KubeClientSet, setup.Role(), f.Namespace.Name, vaultSecretServiceAccount)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			err := vaultaddon.CleanKubernetesRoleForServiceAccountRefAuth(ctx, f.KubeClientSet, setup.Role(), f.Namespace.Name, vaultSecretServiceAccount)
			Expect(err).NotTo(HaveOccurred())
		}()

		By("Creating an Issuer")
		vaultIssuer := gen.IssuerWithRandomName(issuerGeneratorName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(addon.Vault.Details().URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(addon.Vault.Details().VaultCA),
			gen.SetIssuerVaultKubernetesAuthServiceAccount(vaultSecretServiceAccount, setup.Role(), setup.KubernetesAuthPath()))
		vaultIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuerName = vaultIssuer.Name

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})
