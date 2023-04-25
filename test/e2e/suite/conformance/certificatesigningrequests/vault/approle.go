/*
Copyright 2021 The cert-manager Authors.

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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/vault"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificatesigningrequests"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
)

type approle struct {
	testWithRootCA bool

	setup *vault.VaultInitializer

	*secrets
}

type secrets struct {
	roleID   string
	secretID string

	secretName      string
	secretNamespace string
}

var _ = framework.ConformanceDescribe("CertificateSigningRequests", func() {
	issuer := &approle{
		testWithRootCA: true,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault AppRole Issuer With Root CA",
		CreateIssuerFunc: issuer.createIssuer,
		DeleteIssuerFunc: issuer.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()

	issuerNoRoot := &approle{
		testWithRootCA: false,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault AppRole Issuer Without Root CA",
		CreateIssuerFunc: issuerNoRoot.createIssuer,
		DeleteIssuerFunc: issuerNoRoot.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()

	clusterIssuer := &approle{
		testWithRootCA: true,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault AppRole ClusterIssuer With Root CA",
		CreateIssuerFunc: clusterIssuer.createClusterIssuer,
		DeleteIssuerFunc: clusterIssuer.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()

	clusterIssuerNoRoot := &approle{
		testWithRootCA: false,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault AppRole ClusterIssuer Without Root CA",
		CreateIssuerFunc: clusterIssuerNoRoot.createClusterIssuer,
		DeleteIssuerFunc: clusterIssuerNoRoot.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()
})

func (a *approle) delete(f *framework.Framework, signerName string) {
	Expect(a.setup.Clean()).NotTo(HaveOccurred(), "failed to deprovision vault initializer")

	err := f.KubeClientSet.CoreV1().Secrets(a.secretNamespace).Delete(context.TODO(), a.secretName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())

	ref, _ := util.SignerIssuerRefFromSignerName(signerName)
	if kind, _ := util.IssuerKindFromType(ref.Type); kind == cmapi.ClusterIssuerKind {
		err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(context.TODO(), ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

func (a *approle) createIssuer(f *framework.Framework) string {
	appRoleSecretGeneratorName := "vault-approle-secret-"
	By("Creating a VaultAppRole Issuer")

	a.secrets = a.initVault(f)

	sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), vault.NewVaultAppRoleSecret(appRoleSecretGeneratorName, a.secretID), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "vault to store app role secret from vault")

	a.secretName = sec.Name
	a.secretNamespace = sec.Namespace

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-issuer-",
		},
		Spec: a.createIssuerSpec(f),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create vault issuer")

	// wait for issuer to be ready
	By("Waiting for Vault Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("issuers.cert-manager.io/%s.%s", f.Namespace.Name, issuer.Name)
}

func (a *approle) createClusterIssuer(f *framework.Framework) string {
	appRoleSecretGeneratorName := "vault-approle-secret-"
	By("Creating a VaultAppRole ClusterIssuer")

	a.secrets = a.initVault(f)

	sec, err := f.KubeClientSet.CoreV1().Secrets(f.Config.Addons.CertManager.ClusterResourceNamespace).Create(context.TODO(), vault.NewVaultAppRoleSecret(appRoleSecretGeneratorName, a.secretID), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "vault to store app role secret from vault")

	a.secretName = sec.Name
	a.secretNamespace = sec.Namespace

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-cluster-issuer-",
		},
		Spec: a.createIssuerSpec(f),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create vault issuer")

	// wait for issuer to be ready
	By("Waiting for Vault Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}

func (a *approle) initVault(f *framework.Framework) *secrets {
	By("Configuring the VaultAppRole server")
	a.setup = vault.NewVaultInitializerAppRole(
		addon.Base.Details().KubeClient,
		*addon.Vault.Details(),
		a.testWithRootCA,
	)
	Expect(a.setup.Init()).NotTo(HaveOccurred(), "failed to init vault")
	Expect(a.setup.Setup()).NotTo(HaveOccurred(), "failed to setup vault")

	roleID, secretID, err := a.setup.CreateAppRole()
	Expect(err).NotTo(HaveOccurred(), "vault to create app role from vault")

	return &secrets{
		roleID:   roleID,
		secretID: secretID,
	}
}

func (a *approle) createIssuerSpec(f *framework.Framework) cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			Vault: &cmapi.VaultIssuer{
				Server:   addon.Vault.Details().URL,
				Path:     a.setup.IntermediateSignPath(),
				CABundle: addon.Vault.Details().VaultCA,
				Auth: cmapi.VaultAuth{
					AppRole: &cmapi.VaultAppRole{
						Path:   a.setup.AppRoleAuthPath(),
						RoleId: a.roleID,
						SecretRef: cmmeta.SecretKeySelector{
							Key: "secretkey",
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: a.secretName,
							},
						},
					},
				},
			},
		},
	}
}
