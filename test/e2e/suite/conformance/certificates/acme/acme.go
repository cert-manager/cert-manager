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

package acme

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/pebble"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates"
	"github.com/jetstack/cert-manager/test/e2e/suite/issuers/acme/dnsproviders"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	// unsupportedHTTP01Features is a list of features that are not supported by the ACME
	// issuer type using HTTP01
	var unsupportedHTTP01Features = certificates.NewFeatureSet(
		certificates.IPAddressFeature,
		certificates.DurationFeature,
		certificates.WildcardsFeature,
		certificates.URISANsFeature,
		certificates.CommonNameFeature,
	)

	// unsupportedDNS01Features is a list of features that are not supported by the ACME
	// issuer type using DNS01
	var unsupportedDNS01Features = certificates.NewFeatureSet(
		certificates.IPAddressFeature,
		certificates.DurationFeature,
		certificates.URISANsFeature,
		certificates.CommonNameFeature,
	)

	provisionerHTTP01 := new(acmeIssuerProvisioner)
	(&certificates.Suite{
		Name:                "ACME HTTP01",
		CreateIssuerFunc:    provisionerHTTP01.createHTTP01,
		DeleteIssuerFunc:    provisionerHTTP01.delete,
		UnsupportedFeatures: unsupportedHTTP01Features,
	}).Define()

	provisionerDNS01 := new(acmeIssuerProvisioner)
	(&certificates.Suite{
		Name:                "ACME DNS01",
		CreateIssuerFunc:    provisionerDNS01.createDNS01,
		DeleteIssuerFunc:    provisionerDNS01.delete,
		UnsupportedFeatures: unsupportedDNS01Features,
	}).Define()
})

type acmeIssuerProvisioner struct {
	tiller     *tiller.Tiller
	pebble     *pebble.Pebble
	cloudflare *dnsproviders.Cloudflare
}

func (a *acmeIssuerProvisioner) delete(f *framework.Framework, ref cmmeta.ObjectReference) {
	if a.pebble != nil {
		Expect(a.pebble.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision pebble")
	}
	if a.cloudflare != nil {
		Expect(a.cloudflare.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision cloudflare")
	}
	Expect(a.tiller.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision tiller")
}

// createXXX will deploy the required components to run an ACME issuer based test.
// This includes:
// - tiller
// - pebble
// - a properly configured Issuer resource

func (a *acmeIssuerProvisioner) createHTTP01(f *framework.Framework) cmmeta.ObjectReference {
	a.deployTiller(f, "http01")

	a.pebble = &pebble.Pebble{
		Tiller:    a.tiller,
		Name:      "cm-e2e-create-acme-http01-issuer",
		Namespace: f.Namespace.Name,
	}
	Expect(a.pebble.Setup(f.Config)).NotTo(HaveOccurred(), "failed to setup pebble")
	Expect(a.pebble.Provision()).NotTo(HaveOccurred(), "failed to provision pebble")

	By("Creating an ACME HTTP01 issuer")
	issuer := &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acme-issuer-http01",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				ACME: &cmacme.ACMEIssuer{
					Server:        a.pebble.Details().Host,
					SkipTLSVerify: true,
					PrivateKey: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "acme-private-key-http01",
						},
					},
					Solvers: []cmacme.ACMEChallengeSolver{
						{
							HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
								// Not setting the Class or Name field will cause cert-manager to create
								// new ingress resources that do not specify a class to solve challenges,
								// which means all Ingress controllers should act on the ingresses.
								Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
							},
						},
					},
				},
			},
		},
	}

	issuer, err := f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name).Create(issuer)
	Expect(err).NotTo(HaveOccurred(), "failed to create acme HTTP01 issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func (a *acmeIssuerProvisioner) createDNS01(f *framework.Framework) cmmeta.ObjectReference {
	a.deployTiller(f, "dns01")

	a.cloudflare = &dnsproviders.Cloudflare{
		Namespace: f.Namespace.Name,
	}
	Expect(a.cloudflare.Setup(f.Config)).NotTo(HaveOccurred(), "failed to setup cloudflare")
	Expect(a.cloudflare.Provision()).NotTo(HaveOccurred(), "failed to provision cloudflare")

	By("Creating an ACME DNS01 issuer")
	issuer := &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acme-issuer-dns01",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				ACME: &cmacme.ACMEIssuer{
					// Hardcode this to the acme staging endpoint now due to issues with pebble dns resolution
					Server:        "https://acme-staging-v02.api.letsencrypt.org/directory",
					SkipTLSVerify: true,
					PrivateKey: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "acme-private-key",
						},
					},
					Solvers: []cmacme.ACMEChallengeSolver{
						{
							DNS01: &a.cloudflare.Details().ProviderConfig,
						},
					},
				},
			},
		},
	}
	issuer, err := f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name).Create(issuer)
	Expect(err).NotTo(HaveOccurred(), "failed to create acme DNS01 issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func (a *acmeIssuerProvisioner) deployTiller(f *framework.Framework, solverType string) {
	a.tiller = &tiller.Tiller{
		Name:               "tiller-deploy-" + solverType,
		ClusterPermissions: false,
		Namespace:          f.Namespace.Name,
	}
	Expect(a.tiller.Setup(f.Config)).NotTo(HaveOccurred(), "failed to setup tiller")
	Expect(a.tiller.Provision()).NotTo(HaveOccurred(), "failed to provision tiller")
}
