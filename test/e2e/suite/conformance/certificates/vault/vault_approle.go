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
	"path"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon/vault"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/test/e2e/suite/conformance/certificates"
)

const (
	intermediateMount      = "intermediate-ca"
	role                   = "kubernetes-vault"
	vaultSecretAppRoleName = "vault-role-"
	authPath               = "approle"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	var unsupportedFeatures = featureset.NewFeatureSet(
		featureset.KeyUsagesFeature,
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
	vault     *vault.Vault
	vaultInit *vault.VaultInitializer

	*vaultSecrets
}

type vaultSecrets struct {
	roleID   string
	secretID string

	secretName      string
	secretNamespace string
}

func (v *vaultAppRoleProvisioner) delete(f *framework.Framework, ref cmmeta.ObjectReference) {
	Expect(v.vaultInit.Clean()).NotTo(HaveOccurred(), "failed to deprovision vault initializer")
	Expect(v.vault.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision vault")

	err := f.KubeClientSet.CoreV1().Secrets(v.secretNamespace).Delete(context.TODO(), v.secretName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())

	if ref.Kind == "ClusterIssuer" {
		err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(context.TODO(), ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

func (v *vaultAppRoleProvisioner) createIssuer(f *framework.Framework) cmmeta.ObjectReference {
	By("Creating a VaultAppRole Issuer")

	v.vaultSecrets = v.initVault(f)

	sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), vault.NewVaultAppRoleSecret(vaultSecretAppRoleName, v.secretID), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "vault to store app role secret from vault")

	v.secretName = sec.Name
	v.secretNamespace = sec.Namespace

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-issuer-",
		},
		Spec: v.createIssuerSpec(f),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create vault issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func (v *vaultAppRoleProvisioner) createClusterIssuer(f *framework.Framework) cmmeta.ObjectReference {
	By("Creating a VaultAppRole ClusterIssuer")

	v.vaultSecrets = v.initVault(f)

	sec, err := f.KubeClientSet.CoreV1().Secrets(f.Config.Addons.CertManager.ClusterResourceNamespace).Create(context.TODO(), vault.NewVaultAppRoleSecret(vaultSecretAppRoleName, v.secretID), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "vault to store app role secret from vault")

	v.secretName = sec.Name
	v.secretNamespace = sec.Namespace

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-cluster-issuer-",
		},
		Spec: v.createIssuerSpec(f),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create vault issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
}

func (v *vaultAppRoleProvisioner) initVault(f *framework.Framework) *vaultSecrets {
	v.vault = &vault.Vault{
		Base:      addon.Base,
		Namespace: f.Namespace.Name,
		Name:      "cm-e2e-create-vault-issuer",
	}
	Expect(v.vault.Setup(f.Config)).NotTo(HaveOccurred(), "failed to setup vault")
	Expect(v.vault.Provision()).NotTo(HaveOccurred(), "failed to provision vault")

	By("Configuring the VaultAppRole server")
	v.vaultInit = &vault.VaultInitializer{
		Details:           *v.vault.Details(),
		RootMount:         "root-ca",
		IntermediateMount: intermediateMount,
		Role:              role,
		AppRoleAuthPath:   authPath,
	}
	Expect(v.vaultInit.Init()).NotTo(HaveOccurred(), "failed to init vault")
	Expect(v.vaultInit.Setup()).NotTo(HaveOccurred(), "failed to setup vault")

	roleID, secretID, err := v.vaultInit.CreateAppRole()
	Expect(err).NotTo(HaveOccurred(), "vault to create app role from vault")

	return &vaultSecrets{
		roleID:   roleID,
		secretID: secretID,
	}
}

func (v *vaultAppRoleProvisioner) createIssuerSpec(f *framework.Framework) cmapi.IssuerSpec {
	vaultPath := path.Join(intermediateMount, "sign", role)

	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			Vault: &cmapi.VaultIssuer{
				Server:   v.vault.Details().Host,
				Path:     vaultPath,
				CABundle: v.vault.Details().VaultCA,
				Auth: cmapi.VaultAuth{
					AppRole: &cmapi.VaultAppRole{
						Path:   authPath,
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
