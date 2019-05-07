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

package certificate

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/pebble"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/samplewebhook"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
	"github.com/jetstack/cert-manager/test/e2e/util"
	"github.com/jetstack/cert-manager/test/util/generate"
)

var _ = framework.CertManagerDescribe("ACME webhook DNS provider", func() {
	f := framework.NewDefaultFramework("acme-dns01-sample-webhook")
	//h := f.Helper()

	Context("with the sample webhook solver deployed", func() {
		// TODO: add additional DNS provider configs here
		//cf := &dnsproviders.Cloudflare{}

		var (
			tiller = &tiller.Tiller{
				Name:               "tiller-deploy-sample-webhook",
				ClusterPermissions: true,
			}
			pebble = &pebble.Pebble{
				Tiller: tiller,
				Name:   "cm-e2e-acme-dns01-sample-webhook",
			}
			webhook = &samplewebhook.CertmanagerWebhook{
				Name:        "cm-e2e-acme-dns01-sample-webhook",
				Tiller:      tiller,
				Certmanager: addon.CertManager,
			}
		)

		BeforeEach(func() {
			tiller.Namespace = f.Namespace.Name
			pebble.Namespace = f.Namespace.Name
			webhook.Namespace = f.Namespace.Name
		})

		f.RequireGlobalAddon(addon.CertManager)
		f.RequireAddon(tiller)
		f.RequireAddon(pebble)
		f.RequireAddon(webhook)

		issuerName := "test-acme-issuer"
		certificateName := "test-acme-certificate"
		certificateSecretName := "test-acme-certificate"
		dnsDomain := ""

		BeforeEach(func() {
			dnsDomain = "example.com"

			By("Creating an Issuer")
			issuer := generate.Issuer(generate.IssuerConfig{
				Name:               issuerName,
				Namespace:          f.Namespace.Name,
				ACMESkipTLSVerify:  true,
				ACMEServer:         pebble.Details().Host,
				ACMEEmail:          testingACMEEmail,
				ACMEPrivateKeyName: testingACMEPrivateKey,
				DNS01: &v1alpha1.ACMEIssuerDNS01Config{
					Providers: []v1alpha1.ACMEIssuerDNS01Provider{
						{
							Name: "default",
							Webhook: &v1alpha1.ACMEIssuerDNS01ProviderWebhook{
								GroupName:  webhook.Details().GroupName,
								SolverName: webhook.Details().SolverName,
								Config: &v1beta1.JSON{
									Raw: []byte(`{}`),
								},
							},
						},
					},
				},
			})
			issuer, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(issuer)
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
			f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(certificateSecretName, nil)
		})

		It("should call the dummy webhook provider and mark the challenges as presented=true", func() {
			By("Creating a Certificate")

			certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

			cert := generate.Certificate(generate.CertificateConfig{
				Name:       certificateName,
				Namespace:  f.Namespace.Name,
				SecretName: certificateSecretName,
				IssuerName: issuerName,
				DNSNames:   []string{dnsDomain},
				SolverConfig: &v1alpha1.SolverConfig{
					DNS01: &v1alpha1.DNS01SolverConfig{
						Provider: "default",
					},
				},
			})
			cert, err := certClient.Create(cert)
			Expect(err).NotTo(HaveOccurred())

			var order *v1alpha1.Order
			pollErr := wait.PollImmediate(500*time.Millisecond, time.Second*30,
				func() (bool, error) {
					l, err := f.CertManagerClientSet.CertmanagerV1alpha1().Orders(f.Namespace.Name).List(metav1.ListOptions{
						LabelSelector: "acme.cert-manager.io/certificate-name=" + cert.Name,
					})
					Expect(err).NotTo(HaveOccurred())

					log.Logf("Found %d orders for certificate", len(l.Items))
					if len(l.Items) == 1 {
						order = &l.Items[0]
						log.Logf("Found order named %q", order.Name)
						return true, nil
					}

					return false, nil
				},
			)
			Expect(pollErr).NotTo(HaveOccurred())

			pollErr = wait.PollImmediate(500*time.Millisecond, time.Second*30,
				func() (bool, error) {
					l, err := f.CertManagerClientSet.CertmanagerV1alpha1().Challenges(f.Namespace.Name).List(metav1.ListOptions{
						LabelSelector: "acme.cert-manager.io/order-name=" + order.Name,
					})
					Expect(err).NotTo(HaveOccurred())

					log.Logf("Found %d challenges", len(l.Items))
					if len(l.Items) == 0 {
						log.Logf("Waiting for at least one challenge to exist")
						return false, nil
					}

					allPresented := true
					for _, ch := range l.Items {
						log.Logf("Found challenge named %q", ch.Name)

						if ch.Status.Presented == false {
							log.Logf("Challenge %q has not been 'Presented'", ch.Name)
							allPresented = false
						}
					}

					return allPresented, nil
				},
			)
			Expect(pollErr).NotTo(HaveOccurred())
		})
	})
})
