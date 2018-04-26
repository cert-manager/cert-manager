/*
Copyright 2017 Jetstack Ltd.
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

package certificate

import (
	"flag"
	"time"

	"github.com/jetstack/cert-manager/test/util/generate"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmutil "github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/util"
)

var cloudflareEmail string
var cloudflareAPIKey string

func init() {
	flag.StringVar(&cloudflareEmail, "cloudflare-email", "", ""+
		"The cloud API email address. If not specified, DNS tests will be skipped")
	flag.StringVar(&cloudflareAPIKey, "cloudflare-api-key", "", ""+
		"The cloudflare API key. If not specified, DNS tests will be skipped")
}

var _ = framework.CertManagerDescribe("ACME Certificate (DNS01)", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-dns01")

	issuerName := "test-acme-issuer"
	certificateName := "test-acme-certificate"
	certificateSecretName := "test-acme-certificate"
	cloudflareSecretName := "cloudflare-api-token"

	BeforeEach(func() {
		if cloudflareAPIKey == "" {
			framework.Skipf("Skipping DNS01 provider tests as cloudflare api key is blank")
			return
		}

		By("Verifying there is no existing ACME private key")
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(testingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), testingACMEPrivateKey)))
		By("Verifying there is no existing TLS certificate secret")
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(certificateSecretName, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), certificateSecretName)))

		By("Creating the cloudflare api key fixture")
		cfSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cloudflareSecretName,
				Namespace: f.Namespace.Name,
			},
			Data: map[string][]byte{
				"api-key": []byte(cloudflareAPIKey),
			},
		}
		_, err = f.KubeClientSet.CoreV1().Secrets(cfSecret.Namespace).Create(cfSecret)
		Expect(err).NotTo(HaveOccurred())

		By("Creating an Issuer")
		issuer := generate.Issuer(generate.IssuerConfig{
			Name:              issuerName,
			Namespace:         f.Namespace.Name,
			ACMESkipTLSVerify: true,
			// Hardcode this to the acme staging endpoint now due to issues with pebble dns resolution
			ACMEServer: "https://acme-staging-v02.api.letsencrypt.org/directory",
			// ACMEServer:         framework.TestContext.ACMEURL,
			ACMEEmail:          testingACMEEmail,
			ACMEPrivateKeyName: testingACMEPrivateKey,
			DNS01: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "cloudflare",
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: cloudflareEmail,
							APIKey: v1alpha1.SecretKeySelector{
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: cloudflareSecretName,
								},
								Key: "api-key",
							},
						},
					},
				},
			},
		})
		issuer, err = f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(issuer)
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			func(i *v1alpha1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(testingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(testingACMEPrivateKey, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(cloudflareSecretName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(certificateSecretName, nil)
	})

	It("should obtain a signed certificate for a regular domain", func() {
		By("Creating a Certificate")
		dnsName := cmutil.RandStringRunes(5) + "." + util.ACMECloudflareDomain
		cert := generate.Certificate(generate.CertificateConfig{
			Name:       certificateName,
			Namespace:  f.Namespace.Name,
			SecretName: certificateSecretName,
			IssuerName: issuerName,
			DNSNames:   []string{dnsName},
			ACMESolverConfig: v1alpha1.ACMESolverConfig{
				DNS01: &v1alpha1.ACMECertificateDNS01Config{
					Provider: "cloudflare",
				},
			},
		})
		cert, err := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(cert)
		Expect(err).NotTo(HaveOccurred())
		f.WaitCertificateIssuedValid(cert)
	})

	It("should obtain a signed certificate for a wildcard domain", func() {
		By("Creating a Certificate")
		dnsName := cmutil.RandStringRunes(5) + "." + util.ACMECloudflareDomain
		cert := generate.Certificate(generate.CertificateConfig{
			Name:       certificateName,
			Namespace:  f.Namespace.Name,
			SecretName: certificateSecretName,
			IssuerName: issuerName,
			DNSNames:   []string{"*." + dnsName},
			ACMESolverConfig: v1alpha1.ACMESolverConfig{
				DNS01: &v1alpha1.ACMECertificateDNS01Config{
					Provider: "cloudflare",
				},
			},
		})
		cert, err := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(cert)
		Expect(err).NotTo(HaveOccurred())
		f.WaitCertificateIssuedValid(cert)
	})

	It("should obtain a signed certificate for a wildcard and apex domain", func() {
		By("Creating a Certificate")
		dnsName := cmutil.RandStringRunes(5) + "." + util.ACMECloudflareDomain
		cert := generate.Certificate(generate.CertificateConfig{
			Name:       certificateName,
			Namespace:  f.Namespace.Name,
			SecretName: certificateSecretName,
			IssuerName: issuerName,
			DNSNames:   []string{"*." + dnsName, dnsName},
			ACMESolverConfig: v1alpha1.ACMESolverConfig{
				DNS01: &v1alpha1.ACMECertificateDNS01Config{
					Provider: "cloudflare",
				},
			},
		})
		cert, err := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(cert)
		Expect(err).NotTo(HaveOccurred())
		// use a longer timeout for this, as it requires performing 2 dns validations in serial
		f.WaitCertificateIssuedValidTimeout(cert, time.Minute*10)
	})
})
