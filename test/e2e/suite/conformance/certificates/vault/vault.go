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

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	vaultaddon "github.com/jetstack/cert-manager/test/e2e/framework/addon/vault"
	"github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	(&certificates.Suite{
		Name:             "Vault",
		CreateIssuerFunc: createVaultIssuer,
	}).Define()
})

func createVaultIssuer(f *framework.Framework) cmapi.ObjectReference {
	By("Creating a Vault issuer")

	var (
		tiller = &tiller.Tiller{
			Name:               "tiller-deploy",
			Namespace:          f.Namespace.Name,
			ClusterPermissions: false,
		}
		vault = &vaultaddon.Vault{
			Tiller:    tiller,
			Namespace: f.Namespace.Name,
			Name:      "cm-e2e-create-vault-issuer",
		}
	)

	f.RequireAddon(tiller)
	f.RequireAddon(vault)

	intermediateMount := "intermediate-ca"
	role := "kubernetes-vault"
	vaultSecretAppRoleName := "vault-role"
	vaultPath := path.Join(intermediateMount, "sign", role)
	authPath := "approle"

	By("Configuring the Vault server")
	vaultInit := &vaultaddon.VaultInitializer{
		Details:           *vault.Details(),
		RootMount:         "root-ca",
		IntermediateMount: intermediateMount,
		Role:              role,
		AuthPath:          authPath,
	}
	err := vaultInit.Init()
	Expect(err).NotTo(HaveOccurred())
	err = vaultInit.Setup()
	Expect(err).NotTo(HaveOccurred())
	roleID, secretID, err := vaultInit.CreateAppRole()
	Expect(err).NotTo(HaveOccurred())

	_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(vaultaddon.NewVaultAppRoleSecret(vaultSecretAppRoleName, secretID))
	Expect(err).NotTo(HaveOccurred())

	issuer, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(&cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vault-issuer",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				Vault: &cmapi.VaultIssuer{
					Server:   vault.Details().Host,
					Path:     vaultPath,
					CABundle: vault.Details().VaultCA,
					Auth: cmapi.VaultAuth{
						AppRole: cmapi.VaultAppRole{
							Path:   authPath,
							RoleId: roleID,
							SecretRef: cmapi.SecretKeySelector{
								Key: "secretkey",
								LocalObjectReference: cmapi.LocalObjectReference{
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

	return cmapi.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}
