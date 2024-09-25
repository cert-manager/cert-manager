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

package certificate

import (
	"context"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
	"github.com/cert-manager/cert-manager/e2e-tests/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CertManagerDescribe("ACME webhook DNS provider", func() {
	f := framework.NewDefaultFramework("acme-dns01-sample-webhook")
	ctx := context.TODO()

	Context("with the sample webhook solver deployed", func() {
		issuerName := "test-acme-issuer"
		certificateName := "test-acme-certificate"
		certificateSecretName := "test-acme-certificate"
		dnsDomain := ""

		BeforeEach(func() {
			dnsDomain = "example.com"

			By("Creating an Issuer")
			issuer := gen.Issuer(issuerName,
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					SkipTLSVerify: true,
					Server:        f.Config.Addons.ACMEServer.URL,
					Email:         f.Config.Addons.ACMEServer.TestingACMEEmail,
					PrivateKey: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: f.Config.Addons.ACMEServer.TestingACMEPrivateKey,
						},
					},
					Solvers: []cmacme.ACMEChallengeSolver{
						{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Webhook: &cmacme.ACMEIssuerDNS01ProviderWebhook{
									GroupName:  f.Config.Addons.DNS01Webhook.GroupName,
									SolverName: f.Config.Addons.DNS01Webhook.SolverName,
									Config: &apiextensionsv1.JSON{
										Raw: []byte(`{}`),
									},
								},
							},
						},
					},
				}))
			issuer.Namespace = f.Namespace.Name
			_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Waiting for Issuer to become Ready")
			err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
				issuerName,
				v1.IssuerCondition{
					Type:   v1.IssuerConditionReady,
					Status: cmmeta.ConditionTrue,
				})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the ACME account URI is set")
			err = util.WaitForIssuerStatusFunc(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
				issuerName,
				func(i *v1.Issuer) (bool, error) {
					if i.GetStatus().ACMEStatus().URI == "" {
						return false, nil
					}
					return true, nil
				})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying ACME account private key exists")
			secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(ctx, f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			if len(secret.Data) != 1 {
				Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
			}
		})

		AfterEach(func() {
			By("Cleaning up")
			err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, issuerName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(ctx, f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should call the dummy webhook provider and mark the challenges as presented=true", func() {
			By("Creating a Certificate")

			certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

			cert := gen.Certificate(certificateName,
				gen.SetCertificateSecretName(certificateSecretName),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
				gen.SetCertificateDNSNames(dnsDomain),
			)
			cert.Namespace = f.Namespace.Name

			cert, err := certClient.Create(ctx, cert, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			var order *cmacme.Order
			logf, done := log.LogBackoff()
			defer done()
			pollErr := wait.PollUntilContextTimeout(ctx, 2*time.Second, time.Minute*1, true, func(ctx context.Context) (bool, error) {
				orders, err := listOwnedOrders(ctx, f.CertManagerClientSet, cert)
				Expect(err).NotTo(HaveOccurred())

				logf("Found %d orders for certificate", len(orders))
				if len(orders) == 1 {
					order = orders[0]
					logf("Found order named %q", order.Name)
					return true, nil
				}

				logf("Waiting as one Order should exist, but we found %d", len(orders))
				return false, nil
			})
			Expect(pollErr).NotTo(HaveOccurred())

			logf, done = log.LogBackoff()
			defer done()
			pollErr = wait.PollUntilContextTimeout(ctx, 2*time.Second, time.Minute*3, true, func(ctx context.Context) (bool, error) {
				l, err := listOwnedChallenges(ctx, f.CertManagerClientSet, order)
				Expect(err).NotTo(HaveOccurred())

				logf("Found %d challenges", len(l))
				if len(l) == 0 {
					logf("Waiting for at least one challenge to exist")
					return false, nil
				}

				allPresented := true
				for _, ch := range l {
					logf("Found challenge named %q", ch.Name)

					if !ch.Status.Presented {
						logf("Challenge %q has not been 'Presented'", ch.Name)
						allPresented = false
					}
				}

				return allPresented, nil
			})
			Expect(pollErr).NotTo(HaveOccurred())
		})
	})
})

func listOwnedChallenges(ctx context.Context, cl versioned.Interface, owner *cmacme.Order) ([]*cmacme.Challenge, error) {
	l, err := cl.AcmeV1().Challenges(owner.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var owned []*cmacme.Challenge
	for _, ch := range l.Items {
		if !metav1.IsControlledBy(&ch, owner) {
			continue
		}
		owned = append(owned, &ch)
	}

	return owned, nil
}

func listOwnedOrders(ctx context.Context, cl versioned.Interface, owner *v1.Certificate) ([]*cmacme.Order, error) {
	l, err := cl.AcmeV1().Orders(owner.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var owned []*cmacme.Order
	for _, o := range l.Items {
		v, ok := o.Annotations[v1.CertificateNameKey]
		if !ok || v != owner.Name {
			continue
		}
		owned = append(owned, &o)
	}

	return owned, nil
}
