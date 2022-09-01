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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon"
	vaultaddon "github.com/cert-manager/cert-manager/test/e2e/framework/addon/vault"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/validation"
	"github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var _ = framework.CertManagerDescribe("Vault Issuer Certificate (AppRole, CA without root)", func() {
	fs := featureset.NewFeatureSet(featureset.SaveRootCAToSecret)
	runVaultAppRoleTests(cmapi.IssuerKind, false, fs)
})
var _ = framework.CertManagerDescribe("Vault Issuer Certificate (AppRole, CA with root)", func() {
	fs := featureset.NewFeatureSet()
	runVaultAppRoleTests(cmapi.IssuerKind, true, fs)
})

var _ = framework.CertManagerDescribe("Vault ClusterIssuer Certificate (AppRole, CA without root)", func() {
	fs := featureset.NewFeatureSet(featureset.SaveRootCAToSecret)
	runVaultAppRoleTests(cmapi.ClusterIssuerKind, false, fs)
})
var _ = framework.CertManagerDescribe("Vault ClusterIssuer Certificate (AppRole, CA with root)", func() {
	fs := featureset.NewFeatureSet()
	runVaultAppRoleTests(cmapi.ClusterIssuerKind, true, fs)
})

func runVaultAppRoleTests(issuerKind string, testWithRoot bool, unsupportedFeatures featureset.FeatureSet) {
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
	role := "kubernetes-vault"
	certificateName := "test-vault-certificate"
	certificateSecretName := "test-vault-certificate"
	vaultSecretAppRoleName := "vault-role"
	vaultPath := path.Join(intermediateMount, "sign", role)
	authPath := "approle"
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
			ConfigureWithRoot: testWithRoot,
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
		cert, err := certClient.Create(context.TODO(), util.NewCertManagerVaultCertificate(certificateName, certificateSecretName, vaultIssuerName, issuerKind, nil, nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(cert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(cert, validation.CertificateSetForUnsupportedFeatureSet(unsupportedFeatures)...)
		Expect(err).NotTo(HaveOccurred())

	})

	cases := []struct {
		inputDuration    *metav1.Duration
		inputRenewBefore *metav1.Duration
		expectedDuration time.Duration
		label            string
		event            string
	}{
		{
			inputDuration:    &metav1.Duration{Duration: time.Hour * 24 * 35},
			inputRenewBefore: nil,
			expectedDuration: time.Hour * 24 * 35,
			label:            "valid for 35 days",
		},
		{
			inputDuration:    nil,
			inputRenewBefore: nil,
			expectedDuration: time.Hour * 24 * 90,
			label:            "valid for the default value (90 days)",
		},
		{
			inputDuration:    &metav1.Duration{Duration: time.Hour * 24 * 365},
			inputRenewBefore: nil,
			expectedDuration: time.Hour * 24 * 90,
			label:            "with Vault configured maximum TTL duration (90 days) when requested duration is greater than TTL",
		},
		{
			inputDuration:    &metav1.Duration{Duration: time.Hour * 24 * 240},
			inputRenewBefore: &metav1.Duration{Duration: time.Hour * 24 * 120},
			expectedDuration: time.Hour * 24 * 90,
			label:            "with a warning event when renewBefore is bigger than the duration",
		},
	}

	for _, v := range cases {
		v := v
		It("should generate a new certificate "+v.label, func() {
			By("Creating an Issuer")

			var err error
			if issuerKind == cmapi.IssuerKind {
				vaultIssuer := gen.IssuerWithRandomName("test-vault-issuer-",
					gen.SetIssuerNamespace(f.Namespace.Name),
					gen.SetIssuerVaultURL(vault.Details().Host),
					gen.SetIssuerVaultPath(vaultPath),
					gen.SetIssuerVaultCABundle(vault.Details().VaultCA),
					gen.SetIssuerVaultAppRoleAuth("secretkey", vaultSecretName, roleId, authPath))
				iss, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				vaultIssuerName = iss.Name
			} else {
				vaultIssuer := gen.ClusterIssuerWithRandomName("test-vault-issuer-",
					gen.SetIssuerVaultURL(vault.Details().Host),
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
			cert, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(context.TODO(), util.NewCertManagerVaultCertificate(certificateName, certificateSecretName, vaultIssuerName, issuerKind, v.inputDuration, v.inputRenewBefore), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(cert, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(cert, validation.CertificateSetForUnsupportedFeatureSet(unsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())

			// Vault subtract 30 seconds to the NotBefore date.
			f.CertificateDurationValid(cert, v.expectedDuration, time.Second*30)
		})
	}
}
