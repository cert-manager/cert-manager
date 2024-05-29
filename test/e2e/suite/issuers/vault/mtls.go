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

var _ = framework.CertManagerDescribe("Vault Issuer [mtls]", func() {
	f := framework.NewDefaultFramework("create-vault-issuer")
	ctx := context.TODO()

	issuerName := "test-vault-issuer"
	vaultSecretServiceAccount := "vault-serviceaccount"
	vaultClientCertificateSecretName := "vault-client-cert-secret-" + rand.String(5)
	var roleId, secretId, vaultSecretName string

	appRoleSecretGeneratorName := "vault-approle-secret-"
	var setup *vaultaddon.VaultInitializer

	details := addon.VaultEnforceMtls.Details()

	BeforeEach(func() {
		By("Configuring the Vault server")

		setup = vaultaddon.NewVaultInitializerAllAuth(
			addon.Base.Details().KubeClient,
			*details,
			false,
			"https://kubernetes.default.svc.cluster.local",
		)
		Expect(setup.Init(ctx)).NotTo(HaveOccurred(), "failed to init vault")
		Expect(setup.Setup(ctx)).NotTo(HaveOccurred(), "failed to setup vault")

		var err error
		roleId, secretId, err = setup.CreateAppRole(ctx)
		Expect(err).NotTo(HaveOccurred())

		By("creating a service account for Vault authentication")
		err = setup.CreateKubernetesRole(ctx, f.KubeClientSet, f.Namespace.Name, vaultSecretServiceAccount)
		Expect(err).NotTo(HaveOccurred())

		By("creating a client certificate for Vault mTLS")
		secret := vaultaddon.NewVaultClientCertificateSecret(vaultClientCertificateSecretName, details.VaultClientCertificate, details.VaultClientPrivateKey)
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, secret, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	JustAfterEach(func() {
		By("Cleaning up AppRole")
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, issuerName, metav1.DeleteOptions{})
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(ctx, vaultSecretName, metav1.DeleteOptions{})
		setup.CleanAppRole(ctx)

		By("Cleaning up Kubernetes")
		setup.CleanKubernetesRole(ctx, f.KubeClientSet, f.Namespace.Name, vaultSecretServiceAccount)

		By("Cleaning up Vault")
		Expect(setup.Clean(ctx)).NotTo(HaveOccurred())
	})

	It("should be ready with a valid AppRole", func() {
		sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, vaultaddon.NewVaultAppRoleSecret(appRoleSecretGeneratorName, secretId), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultSecretName = sec.Name

		vaultIssuer := gen.IssuerWithRandomName(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(details.VaultCA),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultAppRoleAuth("secretkey", vaultSecretName, roleId, setup.AppRoleAuthPath()))
		iss, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			iss.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init with missing client certificates", func() {
		sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, vaultaddon.NewVaultAppRoleSecret(appRoleSecretGeneratorName, secretId), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultSecretName = sec.Name

		By("Creating an Issuer")
		vaultIssuer := gen.IssuerWithRandomName(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(details.VaultCA),
			gen.SetIssuerVaultAppRoleAuth("secretkey", vaultSecretName, roleId, setup.AppRoleAuthPath()))
		iss, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			iss.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init with missing Vault AppRole", func() {
		By("Creating an Issuer")
		vaultIssuer := gen.IssuerWithRandomName(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(details.VaultCA),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultAppRoleAuth("secretkey", roleId, setup.Role(), setup.AppRoleAuthPath()))
		iss, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			iss.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init with missing Vault Token", func() {
		By("Creating an Issuer")
		vaultIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(details.VaultCA),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultTokenAuth("secretkey", "vault-token"))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be ready with a valid Kubernetes Role and ServiceAccount Secret", func() {
		saTokenSecretName := "vault-sa-secret-" + rand.String(5)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, vaultaddon.NewVaultKubernetesSecret(saTokenSecretName, vaultSecretServiceAccount), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(details.VaultCA),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		_, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
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
		vaultIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(details.VaultCA),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init when both caBundle and caBundleSecretRef are set", func() {
		By("Creating an Issuer")
		vaultIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(details.VaultCA),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultCABundleSecretRef("ca-bundle", f.Namespace.Name, "ca.crt"))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(
			"spec.vault.caBundle: Invalid value: \"<snip>\": specified caBundle and caBundleSecretRef cannot be used together",
		))
		Expect(err.Error()).To(ContainSubstring("spec.vault.caBundleSecretRef: Invalid value: \"ca-bundle\": specified caBundleSecretRef and caBundle cannot be used together"))
	})

	It("should be ready with a caBundle from a Kubernetes Secret", func() {
		saTokenSecretName := "vault-sa-secret-" + rand.String(5)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, vaultaddon.NewVaultKubernetesSecret(saTokenSecretName, vaultSecretServiceAccount), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ca-bundle",
			},
			Type: "Opaque",
			Data: map[string][]byte{
				"ca.crt": details.VaultCA,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundleSecretRef("ca-bundle", f.Namespace.Name, "ca.crt"),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		_, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be eventually ready when the CA bundle secret gets created after the Issuer", func() {
		saTokenSecretName := "vault-sa-secret-" + rand.String(5)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, vaultaddon.NewVaultKubernetesSecret(saTokenSecretName, vaultSecretServiceAccount), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundleSecretRef("ca-bundle", f.Namespace.Name, "ca.crt"),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		_, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Validate that the Issuer is not ready yet")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())

		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ca-bundle",
			},
			Type: "Opaque",
			Data: map[string][]byte{
				"ca.crt": details.VaultCA,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be eventually ready when the Vault client certificate secret gets created after the Issuer", func() {
		sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, vaultaddon.NewVaultAppRoleSecret(appRoleSecretGeneratorName, secretId), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultSecretName = sec.Name
		customVaultClientCertificateSecretName := "vault-client-cert-secret-custom-" + rand.String(5)

		vaultIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(details.VaultCA),
			gen.SetIssuerVaultClientCertSecretRef(customVaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(customVaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultAppRoleAuth("secretkey", vaultSecretName, roleId, setup.AppRoleAuthPath()))
		iss, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Validate that the Issuer is not ready yet")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())

		By("creating a client certificate for Vault mTLS")
		secret := vaultaddon.NewVaultClientCertificateSecret(customVaultClientCertificateSecretName, details.VaultClientCertificate, details.VaultClientPrivateKey)
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, secret, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			iss.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("it should become not ready when the CA certificate in the secret changes and doesn't match Vault's CA anymore", func() {
		saTokenSecretName := "vault-sa-secret-" + rand.String(5)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, vaultaddon.NewVaultKubernetesSecret(saTokenSecretName, vaultSecretServiceAccount), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ca-bundle",
			},
			Type: "Opaque",
			Data: map[string][]byte{
				"ca.crt": details.VaultCA,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vaultIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundleSecretRef("ca-bundle", f.Namespace.Name, "ca.crt"),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultKubernetesAuthSecret("token", saTokenSecretName, setup.Role(), setup.KubernetesAuthPath()))
		_, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Updating CA bundle")
		public, _, err := vaultaddon.GenerateCA()
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(ctx, &corev1.Secret{
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
			issuerName,
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
		vaultaddon.CreateKubernetesRoleForServiceAccountRefAuth(ctx, f.KubeClientSet, setup.Role(), f.Namespace.Name, vaultSecretServiceAccount)
		defer vaultaddon.CleanKubernetesRoleForServiceAccountRefAuth(ctx, f.KubeClientSet, setup.Role(), f.Namespace.Name, vaultSecretServiceAccount)

		By("Creating an Issuer")
		vaultIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(details.URL),
			gen.SetIssuerVaultPath(setup.IntermediateSignPath()),
			gen.SetIssuerVaultCABundle(details.VaultCA),
			gen.SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, corev1.TLSCertKey),
			gen.SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, corev1.TLSPrivateKeyKey),
			gen.SetIssuerVaultKubernetesAuthServiceAccount(vaultSecretServiceAccount, setup.Role(), setup.KubernetesAuthPath()))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})
