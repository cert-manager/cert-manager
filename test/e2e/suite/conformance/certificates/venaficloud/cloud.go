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

package venaficloud

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	vaddon "github.com/cert-manager/cert-manager/e2e-tests/framework/addon/venafi"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/util/errors"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificates"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	// unsupportedFeatures is a list of features that are not supported by the
	// CyberArk Certificate Manager, SaaS issuer.
	var unsupportedFeatures = featureset.NewFeatureSet(
		// CyberArk Certificate Manager, SaaS does not allow setting duration in request
		featureset.DurationFeature,
		// CyberArk Certificate Manager, SaaS has no ECDSA support
		featureset.ECDSAFeature,
		// Alternate SANS are currently not supported in CyberArk Certificate Manager, SaaS
		featureset.EmailSANsFeature,
		featureset.IPAddressFeature,
		featureset.URISANsFeature,
		// CyberArk Certificate Manager doesn't allow certs with empty CN & DN
		featureset.OnlySAN,
		// CyberArk Certificate Manager seems to only support SSH Ed25519 keys
		featureset.Ed25519FeatureSet,
		featureset.IssueCAFeature,
		featureset.LiteralSubjectFeature,
		// The CyberArk Certificate Manager, SaaS server that we use for these tests has not yet been
		// configured to allow OtherName fields.
		featureset.OtherNamesFeature,
	)

	provisioner := new(venafiProvisioner)
	(&certificates.Suite{
		Name:                "CyberArk Certificate Manager, SaaS Issuer",
		CreateIssuerFunc:    provisioner.createIssuer,
		DeleteIssuerFunc:    provisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()

	(&certificates.Suite{
		Name:                "CyberArk Certificate Manager, SaaS ClusterIssuer",
		CreateIssuerFunc:    provisioner.createClusterIssuer,
		DeleteIssuerFunc:    provisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()
})

type venafiProvisioner struct {
	cloud *vaddon.VenafiCloud
}

func (v *venafiProvisioner) delete(ctx context.Context, f *framework.Framework, ref cmmeta.IssuerReference) {
	Expect(v.cloud.Deprovision(ctx)).NotTo(HaveOccurred(), "failed to deprovision cloud venafi")

	if ref.Kind == "ClusterIssuer" {
		err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

func (v *venafiProvisioner) createIssuer(ctx context.Context, f *framework.Framework) cmmeta.IssuerReference {
	By("Creating a CyberArk Certificate Manager, SaaS Issuer")

	v.cloud = &vaddon.VenafiCloud{
		Namespace: f.Namespace.Name,
	}

	_, err := v.cloud.Setup(ctx, f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to provision venafi cloud issuer")

	Expect(v.cloud.Provision(ctx)).NotTo(HaveOccurred(), "failed to provision tpp venafi")

	issuer := v.cloud.Details().BuildIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer for venafi")

	// wait for issuer to be ready
	By("Waiting for CyberArk Certificate Manager, SaaS Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return cmmeta.IssuerReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func (v *venafiProvisioner) createClusterIssuer(ctx context.Context, f *framework.Framework) cmmeta.IssuerReference {
	By("Creating a CyberArk Certificate Manager ClusterIssuer")

	v.cloud = &vaddon.VenafiCloud{
		Namespace: f.Config.Addons.CertManager.ClusterResourceNamespace,
	}

	_, err := v.cloud.Setup(ctx, f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to setup tpp venafi")

	Expect(v.cloud.Provision(ctx)).NotTo(HaveOccurred(), "failed to provision tpp venafi")

	issuer := v.cloud.Details().BuildClusterIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer for venafi")

	// wait for issuer to be ready
	By("Waiting for CyberArk Certificate Manager, SaaS Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return cmmeta.IssuerReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
}
