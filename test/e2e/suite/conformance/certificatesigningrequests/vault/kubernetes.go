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
	"path"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	csrutil "github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon/vault"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/test/e2e/suite/conformance/certificatesigningrequests"
)

var _ = framework.ConformanceDescribe("CertificateSigningRequests", func() {
	issuer := &kubernetes{
		testWithRootCA: true,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault Kubernetes Auth Issuer With Root CA",
		CreateIssuerFunc: issuer.createIssuer,
		DeleteIssuerFunc: issuer.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()

	clusterIssuer := &kubernetes{
		testWithRootCA: true,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault Kubernetes Auth ClusterIssuer With Root CA",
		CreateIssuerFunc: clusterIssuer.createClusterIssuer,
		DeleteIssuerFunc: clusterIssuer.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()
})

type kubernetes struct {
	testWithRootCA bool
	role           string

	addon       *vault.Vault
	initializer *vault.VaultInitializer
}

func (k *kubernetes) createIssuer(f *framework.Framework) string {
	k.initVault(f, f.Namespace.Name)

	By("Creating a VaultKubernetes Issuer")
	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-issuer-",
			Namespace:    f.Namespace.Name,
		},
		Spec: k.issuerSpec(f),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	// wait for issuer to be ready
	By("Waiting for VaultKubernetes Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("issuers.cert-manager.io/%s.%s", issuer.Namespace, issuer.Name)
}

func (k *kubernetes) createClusterIssuer(f *framework.Framework) string {
	k.initVault(f, f.Config.Addons.CertManager.ClusterResourceNamespace)

	By("Creating a VaultKubernetes ClusterIssuer")
	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-issuer-",
		},
		Spec: k.issuerSpec(f),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	// wait for issuer to be ready
	By("Waiting for VaultKubernetes Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}

func (k *kubernetes) delete(f *framework.Framework, signerName string) {
	ref, _ := csrutil.SignerIssuerRefFromSignerName(signerName)
	if kind, _ := csrutil.IssuerKindFromType(ref.Type); kind == cmapi.ClusterIssuerKind {
		err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(context.TODO(), ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		k.initializer.CleanKubernetesRole(f.KubeClientSet, f.Config.Addons.CertManager.ClusterResourceNamespace, k.role, k.role)
	}

	Expect(k.initializer.Clean()).NotTo(HaveOccurred(), "failed to deprovision vault initializer")
	Expect(k.addon.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision vault")

}

func (k *kubernetes) initVault(f *framework.Framework, ns string) {
	By("Configuring the Vault server")
	k.addon = &vault.Vault{
		Base:      addon.Base,
		Name:      "cm-e2e-create-vault-issuer",
		Namespace: f.Namespace.Name,
	}

	k.role = "vault-issuer-" + util.RandStringRunes(5)

	Expect(k.addon.Setup(f.Config)).NotTo(HaveOccurred(), "failed to setup vault")
	Expect(k.addon.Provision()).NotTo(HaveOccurred(), "failed to provision vault")

	By("Configuring the VaultKubernetes server")

	apiHost := "https://kubernetes.default.svc.cluster.local" // since vault is running in-cluster
	caCert := string(f.KubeClientConfig.CAData)
	Expect(caCert).NotTo(BeEmpty())
	Expect(apiHost).NotTo(BeEmpty())
	k.initializer = &vault.VaultInitializer{
		Details:            *k.addon.Details(),
		RootMount:          rootMount,
		IntermediateMount:  intermediateMount,
		ConfigureWithRoot:  k.testWithRootCA,
		KubernetesAuthPath: "kubernetes",
		Role:               k.role,
		APIServerURL:       apiHost,
		APIServerCA:        caCert,
	}
	Expect(k.initializer.Init()).NotTo(HaveOccurred(), "failed to init vault")
	Expect(k.initializer.Setup()).NotTo(HaveOccurred(), "failed to setup vault")

	By("Creating a ServiceAccount for Vault authentication")
	err := k.initializer.CreateKubernetesRole(f.KubeClientSet, ns, k.role, k.role)
	Expect(err).NotTo(HaveOccurred())
	_, err = f.KubeClientSet.CoreV1().Secrets(ns).Create(context.TODO(), vault.NewVaultKubernetesSecret(k.role, k.role), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, _, err = k.initializer.CreateAppRole()
	Expect(err).NotTo(HaveOccurred())
}

func (k *kubernetes) issuerSpec(f *framework.Framework) cmapi.IssuerSpec {
	vaultPath := path.Join(intermediateMount, "sign", k.role)

	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			Vault: &cmapi.VaultIssuer{
				Server:   k.addon.Details().Host,
				Path:     vaultPath,
				CABundle: k.addon.Details().VaultCA,
				Auth: cmapi.VaultAuth{
					Kubernetes: &cmapi.VaultKubernetesAuth{
						Path: "/v1/auth/kubernetes",
						Role: k.role,
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: k.role,
							},
						},
					},
				},
			},
		},
	}
}
