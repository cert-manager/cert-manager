/*
Copyright 2024 The cert-manager Authors.

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

package venafingts

import (
	"context"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	vaddon "github.com/cert-manager/cert-manager/e2e-tests/framework/addon/venafi"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/util/errors"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificates"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	// NGTS shares the same feature limitations as Venafi Cloud.
	var unsupportedFeatures = featureset.NewFeatureSet(
		featureset.DurationFeature,
		featureset.ECDSAFeature,
		featureset.EmailSANsFeature,
		featureset.IPAddressFeature,
		featureset.URISANsFeature,
		featureset.OnlySAN,
		featureset.Ed25519FeatureSet,
		featureset.IssueCAFeature,
		featureset.LiteralSubjectFeature,
		featureset.OtherNamesFeature,
	)

	provisioner := new(ngtsProvisioner)
	(&certificates.Suite{
		Name:                "Venafi NGTS Issuer",
		CreateIssuerFunc:    provisioner.createIssuer,
		DeleteIssuerFunc:    provisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()

	(&certificates.Suite{
		Name:                "Venafi NGTS ClusterIssuer",
		CreateIssuerFunc:    provisioner.createClusterIssuer,
		DeleteIssuerFunc:    provisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()
})

type ngtsProvisioner struct {
	ngts *vaddon.VenafiNGTS
}

func (v *ngtsProvisioner) delete(ctx context.Context, f *framework.Framework, ref cmmeta.IssuerReference) {
	Expect(v.ngts.Deprovision(ctx)).NotTo(HaveOccurred(), "failed to deprovision NGTS venafi")

	if ref.Kind == "ClusterIssuer" {
		err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

func (v *ngtsProvisioner) createIssuer(ctx context.Context, f *framework.Framework) cmmeta.IssuerReference {
	By("Creating a Venafi NGTS Issuer")

	v.ngts = &vaddon.VenafiNGTS{
		Namespace: f.Namespace.Name,
	}

	_, err := v.ngts.Setup(ctx, f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to setup NGTS venafi")

	Expect(v.ngts.Provision(ctx)).NotTo(HaveOccurred(), "failed to provision NGTS venafi")

	issuer := v.ngts.Details().BuildIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer for NGTS venafi")

	By("Waiting for Venafi NGTS Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return cmmeta.IssuerReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func (v *ngtsProvisioner) createClusterIssuer(ctx context.Context, f *framework.Framework) cmmeta.IssuerReference {
	By("Creating a Venafi NGTS ClusterIssuer")

	v.ngts = &vaddon.VenafiNGTS{
		Namespace: f.Config.Addons.CertManager.ClusterResourceNamespace,
	}

	_, err := v.ngts.Setup(ctx, f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to setup NGTS venafi")

	Expect(v.ngts.Provision(ctx)).NotTo(HaveOccurred(), "failed to provision NGTS venafi")

	issuer := v.ngts.Details().BuildClusterIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create cluster issuer for NGTS venafi")

	By("Waiting for Venafi NGTS ClusterIssuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return cmmeta.IssuerReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
}
