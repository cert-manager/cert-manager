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

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	(&certificates.Suite{
		Name:             "SelfSigned Issuer",
		CreateIssuerFunc: createSelfSignedIssuer,
	}).Define()

	(&certificates.Suite{
		Name:             "SelfSigned ClusterIssuer",
		CreateIssuerFunc: createSelfSignedClusterIssuer,
		DeleteIssuerFunc: deleteSelfSignedClusterIssuer,
	}).Define()
})

func createSelfSignedIssuer(f *framework.Framework) cmmeta.ObjectReference {
	By("Creating a SelfSigned Issuer")

	issuer, err := f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name).Create(&cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-issuer-",
		},
		Spec: createSelfSignedIssuerSpec(),
	})
	Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func deleteSelfSignedClusterIssuer(f *framework.Framework, issuer cmmeta.ObjectReference) {
	err := f.CertManagerClientSet.CertmanagerV1alpha2().ClusterIssuers().Delete(issuer.Name, nil)
	Expect(err).NotTo(HaveOccurred())
}

func createSelfSignedClusterIssuer(f *framework.Framework) cmmeta.ObjectReference {
	By("Creating a SelfSigned ClusterIssuer")

	issuer, err := f.CertManagerClientSet.CertmanagerV1alpha2().ClusterIssuers().Create(&cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-cluster-issuer-",
		},
		Spec: createSelfSignedIssuerSpec(),
	})
	Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
}

func createSelfSignedIssuerSpec() cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: &cmapi.SelfSignedIssuer{},
		},
	}
}
