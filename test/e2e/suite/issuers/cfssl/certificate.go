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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	cfssladdon "github.com/jetstack/cert-manager/test/e2e/framework/addon/cfssl"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

const (
	issuerAuthKeySecret     = "C0DEC0DEC0DEC0DEC0DEC0DE"
	issuerAuthKeySecretName = "test-cfssl-authkey"
)

type certificateTest struct {
	description   string
	name          string
	secretName    string
	profile       string
	issuerName    string
	issuerAuthKey string
}

var _ = framework.CertManagerDescribe("CFSSL Certificate", func() {
	f := framework.NewDefaultFramework("create-cfssl-certificate")
	h := f.Helper()

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

		authKeySecret := cfssladdon.NewAuthKeySecret(issuerAuthKeySecretName, issuerAuthKeySecret)
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(authKeySecret)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(issuerAuthKeySecretName, nil)
	})

	f.RequireAddon(tiller)
	f.RequireAddon(cfssl)

	tests := []certificateTest{
		{
			description: "Provided certificate profile does not require authentication",
			name:        "test-cfssl-certificate-1",
			profile:     "server-no-authentication",
			secretName:  "test-cfssl-secret-1",
			issuerName:  "cfssl-issuer",
		},
		{
			description:   "Provided certificate profile requires authentication",
			name:          "test-cfssl-certificate-2",
			profile:       "server",
			secretName:    "test-cfssl-secret-2",
			issuerName:    "cfssl-issuer",
			issuerAuthKey: issuerAuthKeySecretName,
		},
	}

	for index := range tests {
		test := tests[index]

		Context(test.description, func() {
			BeforeEach(func() {
				By("Creating a cfssl issuer")
				serverURL := cfssl.Details().Host

				issuer := util.NewCertManagerCFSSLIssuer(test.issuerName, serverURL, test.issuerAuthKey)
				_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(issuer)
				Expect(err).NotTo(HaveOccurred())

				By("Waiting for issuer to become ready")
				err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
					test.issuerName,
					cmapi.IssuerCondition{
						Type:   cmapi.IssuerConditionReady,
						Status: cmapi.ConditionTrue,
					})
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				By("Cleaning up")
				f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(test.issuerName, nil)
				f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Delete(test.name, nil)
				f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(test.secretName, nil)
			})

			It("should obtain a signed certificate", func() {
				certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

				By("Verifying there is no existing TLS certificate secret")
				_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(test.secretName, metav1.GetOptions{})
				Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), test.secretName)))

				certificate := util.NewCertManagerCFSSLCertificate(test.name, test.profile, test.secretName, test.issuerName, cmapi.IssuerKind)

				By("Creating a certificate")
				_, err = certClient.Create(certificate)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the certificate is valid")
				err = h.WaitCertificateIssuedValid(f.Namespace.Name, test.name, time.Minute*2)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	}
})
