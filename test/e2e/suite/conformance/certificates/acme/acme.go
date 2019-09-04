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

package selfsigned

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/pebble"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	// unsupportedFeatures is a list of features that are not supported by the ACME
	// issuer type using HTTP01
	var unsupportedFeatures = certificates.NewFeatureSet(
		certificates.IPAddressFeature,
		certificates.Wildcards,
	)

	provisioner := &acmeIssuerProvisioner{setGroupName: false}
	(&certificates.Suite{
		Name:                "ACME HTTP01",
		CreateIssuerFunc:    provisioner.create,
		DeleteIssuerFunc:    provisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()

	// crProvisioner sets the issuerRef.group field on Certificates it creates
	crProvisioner := &acmeIssuerProvisioner{setGroupName: true}
	(&certificates.Suite{
		Name:                "ACME HTTP01 (CertificateRequest)",
		CreateIssuerFunc:    crProvisioner.create,
		DeleteIssuerFunc:    crProvisioner.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()
})

type acmeIssuerProvisioner struct {
	tiller *tiller.Tiller
	pebble *pebble.Pebble
	// if setGroupName is true, the 'group name' field on the IssuerRef will be
	// set the 'certmanager.k8s.io'.
	// Setting the group name will cause the new 'certificate requests' based
	// implementation to be used, however this is not implemented for ACME yet
	// See: https://github.com/jetstack/cert-manager/pull/1943
	setGroupName bool
}

func (a *acmeIssuerProvisioner) delete(f *framework.Framework, ref cmapi.ObjectReference) {
	Expect(a.pebble.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision pebble")
	Expect(a.tiller.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision tiller")
}

// create will deploy the required components to run an ACME issuer based test.
// This includes:
// - tiller
// - pebble
// - a properly configured Issuer resource
func (a *acmeIssuerProvisioner) create(f *framework.Framework) cmapi.ObjectReference {
	a.tiller = &tiller.Tiller{
		Name:               "tiller-deploy",
		ClusterPermissions: false,
		Namespace:          f.Namespace.Name,
	}
	Expect(a.tiller.Setup(f.Config)).NotTo(HaveOccurred(), "failed to setup tiller")
	Expect(a.tiller.Provision()).NotTo(HaveOccurred(), "failed to provision tiller")

	a.pebble = &pebble.Pebble{
		Tiller:    a.tiller,
		Name:      "cm-e2e-create-acme-issuer",
		Namespace: f.Namespace.Name,
	}
	Expect(a.pebble.Setup(f.Config)).NotTo(HaveOccurred(), "failed to setup pebble")
	Expect(a.pebble.Provision()).NotTo(HaveOccurred(), "failed to provision pebble")

	By("Creating an ACME issuer")
	issuer := &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acme-issuer",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				ACME: &cmapi.ACMEIssuer{
					Server:        a.pebble.Details().Host,
					SkipTLSVerify: true,
					PrivateKey: cmapi.SecretKeySelector{
						LocalObjectReference: cmapi.LocalObjectReference{
							Name: "acme-private-key",
						},
					},
					Solvers: []cmapi.ACMEChallengeSolver{
						{
							HTTP01: &cmapi.ACMEChallengeSolverHTTP01{
								// Not setting the Class or Name field will cause cert-manager to create
								// new ingress resources that do not specify a class to solve challenges,
								// which means all Ingress controllers should act on the ingresses.
								Ingress: &cmapi.ACMEChallengeSolverHTTP01Ingress{},
							},
						},
					},
				},
			},
		},
	}
	issuer, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(issuer)
	Expect(err).NotTo(HaveOccurred(), "failed to create acme issuer")

	return cmapi.ObjectReference{
		Group: emptyOrString(a.setGroupName, cmapi.SchemeGroupVersion.Group),
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

// emptyOrString will return the given string 's' if 'set' is true,
// otherwise it will return the empty string.
func emptyOrString(set bool, s string) string {
	if set {
		return s
	}
	return ""
}
