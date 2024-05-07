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

package venafi

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/venafi"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/util/errors"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificatesigningrequests"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.ConformanceDescribe("CertificateSigningRequests", func() {
	// unsupportedFeatures is a list of features that are not supported by the
	// Venafi TPP issuer.
	var unsupportedFeatures = featureset.NewFeatureSet(
		// Venafi TPP doesn't allow setting a duration
		featureset.DurationFeature,
		// Due to the current configuration of the test environment, it does not
		// support signing certificates that pair with an elliptic curve or
		// Ed255119 private keys
		featureset.ECDSAFeature,
		featureset.Ed25519FeatureSet,
		// Our Venafi TPP doesn't allow setting non DNS SANs
		// TODO: investigate options to enable these
		featureset.EmailSANsFeature,
		featureset.URISANsFeature,
		featureset.IPAddressFeature,
		// Venafi doesn't allow certs with empty CN & DN
		featureset.OnlySAN,
		// Venafi doesn't setting key usages.
		featureset.KeyUsagesFeature,
	)

	venafiIssuer := new(tpp)
	(&certificatesigningrequests.Suite{
		Name:                "Venafi TPP Issuer",
		CreateIssuerFunc:    venafiIssuer.createIssuer,
		DeleteIssuerFunc:    venafiIssuer.delete,
		UnsupportedFeatures: unsupportedFeatures,
		DomainSuffix:        fmt.Sprintf("%s-venafi-e2e", rand.String(5)),
	}).Define()

	venafiClusterIssuer := new(tpp)
	(&certificatesigningrequests.Suite{
		Name:                "Venafi TPP Cluster Issuer",
		CreateIssuerFunc:    venafiClusterIssuer.createClusterIssuer,
		DeleteIssuerFunc:    venafiClusterIssuer.delete,
		UnsupportedFeatures: unsupportedFeatures,
		DomainSuffix:        fmt.Sprintf("%s-venafi-e2e", rand.String(5)),
	}).Define()
})

type tpp struct {
	*venafi.VenafiTPP
}

func (t *tpp) delete(ctx context.Context, f *framework.Framework, signerName string) {
	Expect(t.Deprovision(ctx)).NotTo(HaveOccurred(), "failed to deprovision tpp venafi")
	ref, _ := util.SignerIssuerRefFromSignerName(signerName)

	if ref.Type == "clusterissuers" {
		err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

func (t *tpp) createIssuer(ctx context.Context, f *framework.Framework) string {
	By("Creating a Venafi Issuer")

	t.VenafiTPP = &venafi.VenafiTPP{
		Namespace: f.Namespace.Name,
	}

	_, err := t.Setup(f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to setup tpp venafi")

	Expect(t.Provision(ctx)).NotTo(HaveOccurred(), "failed to provision tpp venafi")

	issuer := t.Details().BuildIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer for venafi")

	return fmt.Sprintf("issuers.cert-manager.io/%s.%s", issuer.Namespace, issuer.Name)
}

func (t *tpp) createClusterIssuer(ctx context.Context, f *framework.Framework) string {
	By("Creating a Venafi ClusterIssuer")

	t.VenafiTPP = &venafi.VenafiTPP{
		Namespace: f.Config.Addons.CertManager.ClusterResourceNamespace,
	}

	_, err := t.Setup(f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to setup tpp venafi")

	Expect(t.Provision(ctx)).NotTo(HaveOccurred(), "failed to provision tpp venafi")

	issuer := t.Details().BuildClusterIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer for venafi")

	return fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}
