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

package acme

import (
	"context"
	"encoding/base64"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/test/e2e/suite/conformance/certificates"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	runACMEIssuerTests(nil)
})
var _ = framework.ConformanceDescribe("Certificates with External Account Binding", func() {
	runACMEIssuerTests(&cmacme.ACMEExternalAccountBinding{
		KeyID:        "kid-1",
		KeyAlgorithm: "HS256",
	})
})

func runACMEIssuerTests(eab *cmacme.ACMEExternalAccountBinding) {
	// unsupportedHTTP01Features is a list of features that are not supported by the ACME
	// issuer type using HTTP01
	var unsupportedHTTP01Features = featureset.NewFeatureSet(
		featureset.IPAddressFeature,
		featureset.DurationFeature,
		featureset.WildcardsFeature,
		featureset.URISANsFeature,
		featureset.CommonNameFeature,
		featureset.KeyUsagesFeature,
		featureset.EmailSANsFeature,
		featureset.SaveCAToSecret,
	)

	// unsupportedDNS01Features is a list of features that are not supported by the ACME
	// issuer type using DNS01
	var unsupportedDNS01Features = featureset.NewFeatureSet(
		featureset.IPAddressFeature,
		featureset.DurationFeature,
		featureset.URISANsFeature,
		featureset.CommonNameFeature,
		featureset.KeyUsagesFeature,
		featureset.EmailSANsFeature,
		featureset.SaveCAToSecret,
	)

	provisionerHTTP01 := &acmeIssuerProvisioner{
		eab: eab,
	}

	provisionerDNS01 := &acmeIssuerProvisioner{
		eab: eab,
	}

	(&certificates.Suite{
		Name:                "ACME HTTP01 Issuer",
		CreateIssuerFunc:    provisionerHTTP01.createHTTP01Issuer,
		DeleteIssuerFunc:    provisionerHTTP01.delete,
		UnsupportedFeatures: unsupportedHTTP01Features,
	}).Define()

	(&certificates.Suite{
		Name:                "ACME DNS01 Issuer",
		DomainSuffix:        "dns01.example.com",
		CreateIssuerFunc:    provisionerDNS01.createDNS01Issuer,
		DeleteIssuerFunc:    provisionerDNS01.delete,
		UnsupportedFeatures: unsupportedDNS01Features,
	}).Define()

	(&certificates.Suite{
		Name:                "ACME HTTP01 ClusterIssuer",
		CreateIssuerFunc:    provisionerHTTP01.createHTTP01ClusterIssuer,
		DeleteIssuerFunc:    provisionerHTTP01.delete,
		UnsupportedFeatures: unsupportedHTTP01Features,
	}).Define()

	(&certificates.Suite{
		Name:                "ACME DNS01 ClusterIssuer",
		DomainSuffix:        "dns01.example.com",
		CreateIssuerFunc:    provisionerDNS01.createDNS01ClusterIssuer,
		DeleteIssuerFunc:    provisionerDNS01.delete,
		UnsupportedFeatures: unsupportedDNS01Features,
	}).Define()
}

type acmeIssuerProvisioner struct {
	eab             *cmacme.ACMEExternalAccountBinding
	secretNamespace string
}

func (a *acmeIssuerProvisioner) delete(f *framework.Framework, ref cmmeta.ObjectReference) {
	if a.eab != nil {
		err := f.KubeClientSet.CoreV1().Secrets(a.secretNamespace).Delete(context.TODO(), a.eab.Key.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}

	if ref.Kind == "ClusterIssuer" {
		err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(context.TODO(), ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

// createXXX will deploy the required components to run an ACME issuer based test.
// This includes:
// - tiller
// - pebble
// - a properly configured Issuer resource

func (a *acmeIssuerProvisioner) createHTTP01Issuer(f *framework.Framework) cmmeta.ObjectReference {
	a.ensureEABSecret(f, "")

	By("Creating an ACME HTTP01 Issuer")
	issuer := &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "acme-issuer-http01-",
		},
		Spec: a.createHTTP01IssuerSpec(f.Config.Addons.ACMEServer.URL),
	}

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create acme HTTP01 issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func (a *acmeIssuerProvisioner) createHTTP01ClusterIssuer(f *framework.Framework) cmmeta.ObjectReference {
	a.ensureEABSecret(f, f.Config.Addons.CertManager.ClusterResourceNamespace)

	By("Creating an ACME HTTP01 ClusterIssuer")
	issuer := &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "acme-cluster-issuer-http01-",
		},
		Spec: a.createHTTP01IssuerSpec(f.Config.Addons.ACMEServer.URL),
	}

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create acme HTTP01 cluster issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
}

func (a *acmeIssuerProvisioner) createHTTP01IssuerSpec(serverURL string) cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			ACME: &cmacme.ACMEIssuer{
				Server:        serverURL,
				SkipTLSVerify: true,
				PrivateKey: cmmeta.SecretKeySelector{
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "acme-private-key-http01",
					},
				},
				ExternalAccountBinding: a.eab,
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
	}
}

func (a *acmeIssuerProvisioner) createDNS01Issuer(f *framework.Framework) cmmeta.ObjectReference {
	a.ensureEABSecret(f, f.Namespace.Name)

	By("Creating an ACME DNS01 Issuer")
	issuer := &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "acme-issuer-dns01-",
		},
		Spec: a.createDNS01IssuerSpec(f.Config.Addons.ACMEServer.URL, f.Config.Addons.ACMEServer.DNSServer),
	}
	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create acme DNS01 Issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func (a *acmeIssuerProvisioner) createDNS01ClusterIssuer(f *framework.Framework) cmmeta.ObjectReference {
	a.ensureEABSecret(f, f.Config.Addons.CertManager.ClusterResourceNamespace)

	By("Creating an ACME DNS01 ClusterIssuer")
	issuer := &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "acme-cluster-issuer-dns01-",
		},
		Spec: a.createDNS01IssuerSpec(f.Config.Addons.ACMEServer.URL, f.Config.Addons.ACMEServer.DNSServer),
	}
	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create acme DNS01 ClusterIssuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
}

func (a *acmeIssuerProvisioner) createDNS01IssuerSpec(serverURL, dnsServer string) cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			ACME: &cmacme.ACMEIssuer{
				Server:        serverURL,
				SkipTLSVerify: true,
				PrivateKey: cmmeta.SecretKeySelector{
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "acme-private-key",
					},
				},
				ExternalAccountBinding: a.eab,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
								Nameserver: dnsServer,
							},
						},
					},
				},
			},
		},
	}
}

func (a *acmeIssuerProvisioner) ensureEABSecret(f *framework.Framework, ns string) {
	if a.eab == nil {
		return
	}

	if ns == "" {
		ns = f.Namespace.Name
	}
	sec, err := f.KubeClientSet.CoreV1().Secrets(ns).Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "external-account-binding-",
			Namespace:    ns,
		},
		Data: map[string][]byte{
			// base64 url encode (without padding) the HMAC key
			"key": []byte(base64.RawURLEncoding.EncodeToString([]byte("kid-secret-1"))),
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	a.eab.Key = cmmeta.SecretKeySelector{
		Key: "key",
		LocalObjectReference: cmmeta.LocalObjectReference{
			Name: sec.Name,
		},
	}

	a.secretNamespace = sec.Namespace
}
