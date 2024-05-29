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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/vault"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificates"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	var unsupportedFeatures = featureset.NewFeatureSet(
		featureset.KeyUsagesFeature,
		featureset.SaveRootCAToSecret,
		// Vault does not support signing using Ed25519
		featureset.Ed25519FeatureSet,
		featureset.IssueCAFeature,
		featureset.LiteralSubjectFeature,
	)

	provisioner := new(vaultAppRoleProvisioner)

	(&certificates.Suite{
		Name:                "VaultAppRole Issuer",
		CreateIssuerFunc:    provisioner.createIssuer,
		DeleteIssuerFunc:    provisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()

	(&certificates.Suite{
		Name:                "VaultAppRole ClusterIssuer",
		CreateIssuerFunc:    provisioner.createClusterIssuer,
		DeleteIssuerFunc:    provisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()
})

type vaultAppRoleProvisioner struct {
	setup *vault.VaultInitializer

	*vaultSecrets
}

type vaultSecrets struct {
	roleID   string
	secretID string

	secretName      string
	secretNamespace string
}

func (v *vaultAppRoleProvisioner) delete(ctx context.Context, f *framework.Framework, ref cmmeta.ObjectReference) {
	Expect(v.setup.Clean(ctx)).NotTo(HaveOccurred(), "failed to deprovision vault initializer")

	err := f.KubeClientSet.CoreV1().Secrets(v.secretNamespace).Delete(ctx, v.secretName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())

	if ref.Kind == "ClusterIssuer" {
		err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

func (v *vaultAppRoleProvisioner) createIssuer(ctx context.Context, f *framework.Framework) cmmeta.ObjectReference {
	appRoleSecretGeneratorName := "vault-approle-secret-"
	By("Creating a VaultAppRole Issuer")

	v.vaultSecrets = v.initVault(ctx)

	sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, vault.NewVaultAppRoleSecret(appRoleSecretGeneratorName, v.secretID), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "vault to store app role secret from vault")

	v.secretName = sec.Name
	v.secretNamespace = sec.Namespace

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-issuer-",
		},
		Spec: v.createIssuerSpec(),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create vault issuer")

	// wait for issuer to be ready
	By("Waiting for Vault Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func (v *vaultAppRoleProvisioner) createClusterIssuer(ctx context.Context, f *framework.Framework) cmmeta.ObjectReference {
	appRoleSecretGeneratorName := "vault-approle-secret-"
	By("Creating a VaultAppRole ClusterIssuer")

	v.vaultSecrets = v.initVault(ctx)

	sec, err := f.KubeClientSet.CoreV1().Secrets(f.Config.Addons.CertManager.ClusterResourceNamespace).Create(ctx, vault.NewVaultAppRoleSecret(appRoleSecretGeneratorName, v.secretID), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "vault to store app role secret from vault")

	v.secretName = sec.Name
	v.secretNamespace = sec.Namespace

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-cluster-issuer-",
		},
		Spec: v.createIssuerSpec(),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create vault issuer")

	// wait for issuer to be ready
	By("Waiting for Vault Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
}

func (v *vaultAppRoleProvisioner) initVault(ctx context.Context) *vaultSecrets {
	By("Configuring the VaultAppRole server")
	v.setup = vault.NewVaultInitializerAppRole(
		addon.Base.Details().KubeClient,
		*addon.Vault.Details(),
		false,
	)
	Expect(v.setup.Init(ctx)).NotTo(HaveOccurred(), "failed to init vault")
	Expect(v.setup.Setup(ctx)).NotTo(HaveOccurred(), "failed to setup vault")

	roleID, secretID, err := v.setup.CreateAppRole(ctx)
	Expect(err).NotTo(HaveOccurred(), "vault to create app role from vault")

	return &vaultSecrets{
		roleID:   roleID,
		secretID: secretID,
	}
}

func (v *vaultAppRoleProvisioner) createIssuerSpec() cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			Vault: &cmapi.VaultIssuer{
				Server:   addon.Vault.Details().URL,
				Path:     v.setup.IntermediateSignPath(),
				CABundle: addon.Vault.Details().VaultCA,
				Auth: cmapi.VaultAuth{
					AppRole: &cmapi.VaultAppRole{
						Path:   v.setup.AppRoleAuthPath(),
						RoleId: v.roleID,
						SecretRef: cmmeta.SecretKeySelector{
							Key: "secretkey",
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: v.secretName,
							},
						},
					},
				},
			},
		},
	}
}
