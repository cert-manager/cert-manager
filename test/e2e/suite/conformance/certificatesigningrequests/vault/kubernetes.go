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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/vault"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificatesigningrequests"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	csrutil "github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
	// saTokenSecretName is the name of the Secret containing the service account token
	saTokenSecretName string

	setup *vault.VaultInitializer
}

func (k *kubernetes) createIssuer(ctx context.Context, f *framework.Framework) string {
	k.initVault(ctx, f, f.Namespace.Name)

	By("Creating a VaultKubernetes Issuer")
	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-issuer-",
			Namespace:    f.Namespace.Name,
		},
		Spec: k.issuerSpec(),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	// wait for issuer to be ready
	By("Waiting for VaultKubernetes Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("issuers.cert-manager.io/%s.%s", issuer.Namespace, issuer.Name)
}

func (k *kubernetes) createClusterIssuer(ctx context.Context, f *framework.Framework) string {
	k.initVault(ctx, f, f.Config.Addons.CertManager.ClusterResourceNamespace)

	By("Creating a VaultKubernetes ClusterIssuer")
	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-issuer-",
		},
		Spec: k.issuerSpec(),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	// wait for issuer to be ready
	By("Waiting for VaultKubernetes Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}

func (k *kubernetes) delete(ctx context.Context, f *framework.Framework, signerName string) {
	ref, _ := csrutil.SignerIssuerRefFromSignerName(signerName)
	if kind, _ := csrutil.IssuerKindFromType(ref.Type); kind == cmapi.ClusterIssuerKind {
		err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		k.setup.CleanKubernetesRole(ctx, f.KubeClientSet, f.Config.Addons.CertManager.ClusterResourceNamespace, k.setup.Role())
	}

	Expect(k.setup.Clean(ctx)).NotTo(HaveOccurred(), "failed to deprovision vault initializer")
}

func (k *kubernetes) initVault(ctx context.Context, f *framework.Framework, boundNS string) {
	By("Configuring the VaultKubernetes server")

	k.setup = vault.NewVaultInitializerKubernetes(
		addon.Base.Details().KubeClient,
		*addon.Vault.Details(),
		k.testWithRootCA,
		"https://kubernetes.default.svc.cluster.local",
	)
	Expect(k.setup.Init(ctx)).NotTo(HaveOccurred(), "failed to init vault")
	Expect(k.setup.Setup(ctx)).NotTo(HaveOccurred(), "failed to setup vault")

	By("Creating a ServiceAccount for Vault authentication")

	// boundNS is name of the service account for which a Secret containing the service account token will be created
	boundSA := "vault-issuer-" + rand.String(5)
	err := k.setup.CreateKubernetesRole(ctx, f.KubeClientSet, boundNS, boundSA)
	Expect(err).NotTo(HaveOccurred())

	k.saTokenSecretName = "vault-sa-secret-" + rand.String(5)
	_, err = f.KubeClientSet.CoreV1().Secrets(boundNS).Create(ctx, vault.NewVaultKubernetesSecret(k.saTokenSecretName, boundSA), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func (k *kubernetes) issuerSpec() cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			Vault: &cmapi.VaultIssuer{
				Server:   addon.Vault.Details().URL,
				Path:     k.setup.IntermediateSignPath(),
				CABundle: addon.Vault.Details().VaultCA,
				Auth: cmapi.VaultAuth{
					Kubernetes: &cmapi.VaultKubernetesAuth{
						Path: k.setup.KubernetesAuthPath(),
						Role: k.setup.Role(),
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: k.saTokenSecretName,
							},
						},
					},
				},
			},
		},
	}
}
