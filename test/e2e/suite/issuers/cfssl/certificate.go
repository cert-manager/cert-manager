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

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	cfssladdon "github.com/jetstack/cert-manager/test/e2e/framework/addon/cfssl"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

const (
	issuerAuthKeySecret = "C0DEC0DEC0DEC0DEC0DEC0DE"
	serverAPIPrefix     = "/api/v1/cfssl"
)

var _ = framework.CertManagerDescribe("CFSSL Certificate", func() {
	f := framework.NewDefaultFramework("create-cfssl-certificate")
	h := f.Helper()

	issuerAuthKeySecretName := "test-cfssl-authkey"

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
		caSecretName = cfssl.ReleaseName()
	)

	BeforeEach(func() {
		tiller.Namespace = f.Namespace.Name
		cfssl.Namespace = f.Namespace.Name

		caSecret, err := cfssladdon.NewCASecret(caSecretName)
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(caSecret)
		Expect(err).NotTo(HaveOccurred())
		authKeySecret := cfssladdon.NewAuthKeySecret(issuerAuthKeySecretName, issuerAuthKeySecret)
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(authKeySecret)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(caSecretName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(issuerAuthKeySecretName, nil)
	})

	f.RequireAddon(tiller)
	f.RequireAddon(cfssl)

	tests := []struct {
		contextDesc    string
		certName       string
		certSecretName string
		certProfile    string
		issuerName     string
		authKey        string
	}{
		{
			contextDesc:    "Issuer does not require authentication",
			issuerName:     "cfssl-issuer-no-auth",
			certName:       "test-cfssl-certificate",
			certSecretName: "test-cfssl-secret",
			certProfile:    "server-no-auth",
		},
		{
			contextDesc:    "Issuer requires authentication",
			issuerName:     "cfssl-issuer-with-auth",
			certName:       "test-cfssl-certificate-1",
			certSecretName: "test-cfssl-secret-1",
			certProfile:    "server",
			authKey:        issuerAuthKeySecretName,
		},
	}

	for index := range tests {
		test := tests[index]

		Context(test.contextDesc, func() {
			BeforeEach(func() {
				By("Creating a cfssl issuer")
				serverURL := cfssl.Details().Host

				issuer := util.NewCertManagerCFSSLIssuer(test.issuerName, serverURL, serverAPIPrefix, test.authKey)
				_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(issuer)
				Expect(err).NotTo(HaveOccurred())

				By("Waiting for Issuer to become Ready")
				err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
					test.issuerName,
					v1alpha1.IssuerCondition{
						Type:   v1alpha1.IssuerConditionReady,
						Status: v1alpha1.ConditionTrue,
					})
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				By("Cleaning up")
				f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(test.issuerName, nil)
				f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Delete(test.certName, nil)
				f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(test.certSecretName, nil)
			})

			It("should obtain a signed certificate", func() {
				certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)
				secretClient := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name)

				By("Verifying there is no existing TLS certificate secret")
				_, err := secretClient.Get(test.certSecretName, metav1.GetOptions{})
				Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), test.certSecretName)))

				By("Creating a Certificate using a profile that does not require auth")
				certificate := util.NewCertManagerCFSSLCertificate(test.certName, test.certSecretName, test.issuerName, v1alpha1.IssuerKind)
				certificate.Spec.CFSSL = &v1alpha1.CFSSLCertificateConfig{
					Profile: test.certProfile,
				}
				_, err = certClient.Create(certificate)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the certificate is valid")
				err = h.WaitCertificateIssuedValid(f.Namespace.Name, test.certName, time.Minute*2)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	}
})
