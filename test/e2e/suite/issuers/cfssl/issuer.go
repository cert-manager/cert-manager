/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package cfssl

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	cfssladdon "github.com/jetstack/cert-manager/test/e2e/framework/addon/cfssl"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

const (
	issuerName = "e2e-cfssl-issuer"
)

type issuerTest struct {
	description string
	authKeyName string
}

var _ = framework.CertManagerDescribe("CFSSL Issuer", func() {
	f := framework.NewDefaultFramework("create-cfssl-issuer")

	var (
		tiller = &tiller.Tiller{
			Name:               "tiller-deploy",
			ClusterPermissions: false,
		}
		cfssl = &cfssladdon.Cfssl{
			Tiller:  tiller,
			Name:    "cm-e2e-cfssl",
			AuthKey: issuerAuthKeySecret,
		}
	)

	BeforeEach(func() {
		tiller.Namespace = f.Namespace.Name
		cfssl.Namespace = f.Namespace.Name

		By("Creating a authkey secret fixture")
		authKeySecret := cfssladdon.NewAuthKeySecret(issuerAuthKeySecretName, issuerAuthKeySecret)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(authKeySecret)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(issuerAuthKeySecretName, nil)
	})

	f.RequireAddon(tiller)
	f.RequireAddon(cfssl)

	tests := []issuerTest{
		{
			description: "can create issuer with server url and no authentication key",
		},
		{
			description: "can create issuer with server url and authentication key",
			authKeyName: issuerAuthKeySecretName,
		},
	}

	for index := range tests {
		test := tests[index]

		It(test.description, func() {
			By("Creating a cfssl issuer")
			serverURL := cfssl.Details().Host

			issuer := util.NewCertManagerCFSSLIssuer(issuerName, serverURL, test.authKeyName)
			_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(issuer)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for issuer to become ready")
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
				issuerName,
				v1alpha1.IssuerCondition{
					Type:   v1alpha1.IssuerConditionReady,
					Status: v1alpha1.ConditionTrue,
				})
			Expect(err).NotTo(HaveOccurred())
		})
	}
})
