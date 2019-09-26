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

package vault

import (
	"path"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	vault "github.com/jetstack/cert-manager/test/e2e/framework/addon/vault"
	"github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	provisioner := new(vaultAppRoleProvisioner)

	(&certificates.Suite{
		Name:             "VaultAppRole",
		CreateIssuerFunc: provisioner.create,
		DeleteIssuerFunc: provisioner.delete,
	}).Define()
})

type vaultAppRoleProvisioner struct {
	tiller *tiller.Tiller
	vault  *vault.Vault
}

func (v *vaultAppRoleProvisioner) delete(f *framework.Framework, ref cmmeta.ObjectReference) {
	Expect(v.vault.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision vault")
	Expect(v.tiller.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision tiller")
}

func (v *vaultAppRoleProvisioner) create(f *framework.Framework) cmmeta.ObjectReference {
	By("Creating a VaultAppRole issuer")

	v.tiller = &tiller.Tiller{
		Name:               "tiller-deploy",
		Namespace:          f.Namespace.Name,
		ClusterPermissions: false,
	}
	Expect(v.tiller.Setup(f.Config)).NotTo(HaveOccurred(), "failed to setup tiller")
	Expect(v.tiller.Provision()).NotTo(HaveOccurred(), "failed to provision tiller")

	v.vault = &vault.Vault{
		Tiller:    v.tiller,
		Namespace: f.Namespace.Name,
		Name:      "cm-e2e-create-vault-issuer",
	}
	Expect(v.vault.Setup(f.Config)).NotTo(HaveOccurred(), "failed to setup vault")
	Expect(v.vault.Provision()).NotTo(HaveOccurred(), "failed to provision vault")

	intermediateMount := "intermediate-ca"
	role := "kubernetes-vault"
	vaultSecretAppRoleName := "vault-role"
	vaultPath := path.Join(intermediateMount, "sign", role)
	authPath := "approle"

	By("Configuring the VaultAppRole server")
	vaultInit := &vault.VaultInitializer{
		Details:           *v.vault.Details(),
		RootMount:         "root-ca",
		IntermediateMount: intermediateMount,
		Role:              role,
		AppRoleAuthPath:   authPath,
	}
	Expect(vaultInit.Init()).NotTo(HaveOccurred(), "failed to init vault")
	Expect(vaultInit.Setup()).NotTo(HaveOccurred(), "fauled to setup vault")

	roleID, secretID, err := vaultInit.CreateAppRole()
	Expect(err).NotTo(HaveOccurred(), "vault to create app role from vault")

	_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(vault.NewVaultAppRoleSecret(vaultSecretAppRoleName, secretID))
	Expect(err).NotTo(HaveOccurred(), "vault to store app role secret from vault")

	issuer, err := f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name).Create(&cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vault-issuer",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				Vault: &cmapi.VaultIssuer{
					Server:   v.vault.Details().Host,
					Path:     vaultPath,
					CABundle: v.vault.Details().VaultCA,
					Auth: cmapi.VaultAuth{
						AppRole: &cmapi.VaultAppRole{
							Path:   authPath,
							RoleId: roleID,
							SecretRef: cmmeta.SecretKeySelector{
								Key: "secretkey",
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: vaultSecretAppRoleName,
								},
							},
						},
					},
				},
			},
		},
	})
	Expect(err).NotTo(HaveOccurred(), "failed to create vault issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}
