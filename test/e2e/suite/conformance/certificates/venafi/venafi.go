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

package venafi

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/jetstack/cert-manager/test/e2e/framework/util/errors"
	"github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates"
	vaddon "github.com/jetstack/cert-manager/test/e2e/suite/issuers/venafi/addon"
)

var _ = framework.ConformanceDescribe("[Feature:Issuers:Venafi:TPP] Certificates", func() {
	// unsupportedFeatures is a list of features that are not supported by the
	// Venafi issuer.
	var unsupportedFeatures = featureset.NewFeatureSet(
		// Venafi TPP doesn't allow setting a duration
		featureset.DurationFeature,
		// Due to the current configuration of the test environment, it does not
		// support signing certificates that pair with an elliptic curve private
		// key
		featureset.ECDSAFeature,
		// Our Venafi TPP doesn't allow setting non DNS SANs
		// TODO: investigate options to enable these
		featureset.EmailSANsFeature,
		featureset.URISANsFeature,
		featureset.IPAddressFeature,
		// Venafi doesn't allow certs with empty CN & DN
		featureset.OnlySAN,
	)

	provisioner := new(venafiProvisioner)
	(&certificates.Suite{
		Name:                "Venafi Issuer",
		CreateIssuerFunc:    provisioner.createIssuer,
		DeleteIssuerFunc:    provisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()

	(&certificates.Suite{
		Name:                "Venafi ClusterIssuer",
		CreateIssuerFunc:    provisioner.createClusterIssuer,
		DeleteIssuerFunc:    provisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()
})

type venafiProvisioner struct {
	tpp *vaddon.VenafiTPP
}

func (v *venafiProvisioner) delete(f *framework.Framework, ref cmmeta.ObjectReference) {
	Expect(v.tpp.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision tpp venafi")

	if ref.Kind == "ClusterIssuer" {
		err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(context.TODO(), ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

func (v *venafiProvisioner) createIssuer(f *framework.Framework) cmmeta.ObjectReference {
	By("Creating a Venafi Issuer")

	v.tpp = &vaddon.VenafiTPP{
		Namespace: f.Namespace.Name,
	}

	err := v.tpp.Setup(f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to setup tpp venafi")

	Expect(v.tpp.Provision()).NotTo(HaveOccurred(), "failed to provision tpp venafi")

	issuer := v.tpp.Details().BuildIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer for venafi")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func (v *venafiProvisioner) createClusterIssuer(f *framework.Framework) cmmeta.ObjectReference {
	By("Creating a Venafi ClusterIssuer")

	v.tpp = &vaddon.VenafiTPP{
		Namespace: f.Config.Addons.CertManager.ClusterResourceNamespace,
	}

	err := v.tpp.Setup(f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to setup tpp venafi")

	Expect(v.tpp.Provision()).NotTo(HaveOccurred(), "failed to provision tpp venafi")

	issuer := v.tpp.Details().BuildClusterIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer for venafi")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
}
