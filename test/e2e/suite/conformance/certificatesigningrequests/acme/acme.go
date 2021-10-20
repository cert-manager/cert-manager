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

package acme

import (
	"context"
	"encoding/base64"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests/util"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificatesigningrequests"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	runACMEIssuerTests(nil)
})
var _ = framework.ConformanceDescribe("Certificates with External Account Binding", func() {
	runACMEIssuerTests(&cmacme.ACMEExternalAccountBinding{
		KeyID: "kid-1",
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
	)

	http01 := &acme{
		eab: eab,
	}

	dns01 := &acme{
		eab: eab,
	}

	(&certificatesigningrequests.Suite{
		Name:                "ACME HTTP01 Issuer",
		DomainSuffix:        "ingress-nginx.http01.example.com",
		CreateIssuerFunc:    http01.createHTTP01Issuer,
		DeleteIssuerFunc:    http01.delete,
		UnsupportedFeatures: unsupportedHTTP01Features,
	}).Define()

	(&certificatesigningrequests.Suite{
		Name:                "ACME DNS01 Issuer",
		DomainSuffix:        "dns01.example.com",
		CreateIssuerFunc:    dns01.createDNS01Issuer,
		DeleteIssuerFunc:    dns01.delete,
		UnsupportedFeatures: unsupportedDNS01Features,
	}).Define()

	(&certificatesigningrequests.Suite{
		Name:                "ACME HTTP01 ClusterIssuer",
		DomainSuffix:        "ingress-nginx.http01.example.com",
		CreateIssuerFunc:    http01.createHTTP01ClusterIssuer,
		DeleteIssuerFunc:    http01.delete,
		UnsupportedFeatures: unsupportedHTTP01Features,
	}).Define()

	(&certificatesigningrequests.Suite{
		Name:                "ACME DNS01 ClusterIssuer",
		DomainSuffix:        "dns01.example.com",
		CreateIssuerFunc:    dns01.createDNS01ClusterIssuer,
		DeleteIssuerFunc:    dns01.delete,
		UnsupportedFeatures: unsupportedDNS01Features,
	}).Define()
}

type acme struct {
	eab             *cmacme.ACMEExternalAccountBinding
	secretNamespace string
}

func (a *acme) delete(f *framework.Framework, signerName string) {
	if a.eab != nil {
		err := f.KubeClientSet.CoreV1().Secrets(a.secretNamespace).Delete(context.TODO(), a.eab.Key.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}

	ref, _ := util.SignerIssuerRefFromSignerName(signerName)

	if ref.Type == "clusterissuers" {
		err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(context.TODO(), ref.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}

func (a *acme) ensureEABSecret(f *framework.Framework, ns string) {
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
