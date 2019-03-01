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
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	injctrl "github.com/jetstack/cert-manager/pkg/controller/cainjector"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/util"
	admissionreg "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

var _ = framework.CertManagerDescribe("CA Injector", func() {
	f := framework.NewDefaultFramework("ca-injector")

	issuerName := "inject-cert-issuer"

	Context("for validating webhooks", func() {
		var hookToCleanUp runtime.Object
		BeforeEach(func() {
			By("creating a self-signing issuer")
			issuer := util.NewCertManagerSelfSignedIssuer(issuerName)
			issuer.Namespace = f.Namespace.Name
			Expect(f.CRClient.Create(context.Background(), issuer)).To(Succeed())

			By("Waiting for Issuer to become Ready")
			err := util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
				issuerName,
				certmanager.IssuerCondition{
					Type:   certmanager.IssuerConditionReady,
					Status: certmanager.ConditionTrue,
				})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if hookToCleanUp == nil {
				return
			}
			Expect(f.CRClient.Delete(context.Background(), hookToCleanUp)).To(Succeed())
		})

		setupHook := func(hookPrefix string) (admissionreg.ValidatingWebhookConfiguration, certmanager.Certificate, corev1.Secret) {
			By("creating a validating webhook pointing to a cert")
			someURL := "https://localhost:8675"
			hook := admissionreg.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: hookPrefix + "-hook",
					Annotations: map[string]string{
						injctrl.WantInjectAnnotation: types.NamespacedName{Name: "serving-certs", Namespace: f.Namespace.Name}.String(),
					},
				},
				Webhooks: []admissionreg.Webhook{
					{
						Name: "hook1.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							URL: &someURL,
						},
					},
					{
						Name: "hook2.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							Service: &admissionreg.ServiceReference{
								Name:      "some-svc",
								Namespace: f.Namespace.Name,
							},
						},
					},
				},
			}
			Expect(f.CRClient.Create(context.Background(), &hook)).To(Succeed())
			hookToCleanUp = &hook

			By("creating a certificate")
			secretName := types.NamespacedName{Name: "serving-certs-data", Namespace: f.Namespace.Name}
			cert := util.NewCertManagerBasicCertificate("serving-certs", secretName.Name, issuerName, certmanager.IssuerKind, nil, nil)
			cert.Namespace = f.Namespace.Name
			Expect(f.CRClient.Create(context.Background(), cert)).To(Succeed())

			By("grabbing the corresponding secret")
			var secret corev1.Secret
			Eventually(func() error { return f.CRClient.Get(context.Background(), secretName, &secret) }, "10s", "2s").Should(Succeed())

			By("checking that all webhooks have a populated CA")
			caData := secret.Data["ca.crt"]
			Eventually(func() ([][]byte, error) {
				var newHook admissionreg.ValidatingWebhookConfiguration
				if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: hook.Name}, &newHook); err != nil {
					return nil, err
				}
				return [][]byte{newHook.Webhooks[0].ClientConfig.CABundle, newHook.Webhooks[1].ClientConfig.CABundle}, nil
			}, "10s", "2s").Should(Equal([][]byte{caData, caData}))

			return hook, *cert, secret
		}

		It("should inject a CA into all webhook slots", func() {
			setupHook("injected")
		})

		It("should not inject a CA into webhooks that aren't annotated", func() {
			By("creating a validating webhook not pointing to a cert")
			someURL := "https://localhost:8675"
			hook := admissionreg.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "non-injected-hook",
				},
				Webhooks: []admissionreg.Webhook{
					{
						Name: "hook1.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							URL:      &someURL,
							CABundle: []byte("ca data 1"),
						},
					},
					{
						Name: "hook2.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							Service: &admissionreg.ServiceReference{
								Name:      "some-svc",
								Namespace: f.Namespace.Name,
							},
							CABundle: []byte("ca data 2"),
						},
					},
				},
			}
			Expect(f.CRClient.Create(context.Background(), &hook)).To(Succeed())
			hookToCleanUp = &hook

			By("expecting the CA data to remain in place")
			Consistently(func() ([][]byte, error) {
				var newHook admissionreg.ValidatingWebhookConfiguration
				if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: hook.Name}, &newHook); err != nil {
					return nil, err
				}
				return [][]byte{newHook.Webhooks[0].ClientConfig.CABundle, newHook.Webhooks[1].ClientConfig.CABundle}, nil
			}).Should(Equal([][]byte{hook.Webhooks[0].ClientConfig.CABundle, hook.Webhooks[1].ClientConfig.CABundle}))
		})

		It("should update the webhooks when the certificate is changed", func() {
			hook, cert, _ := setupHook("changed")

			By("grabbing the latest copy of the cert")
			Expect(f.CRClient.Get(context.Background(), types.NamespacedName{Name: cert.Name, Namespace: cert.Namespace}, &cert)).To(Succeed())

			By("changing the name of the corresponding secret in the cert")
			secretName := types.NamespacedName{Name: "other-data", Namespace: f.Namespace.Name}
			cert.Spec.SecretName = secretName.Name
			Expect(f.CRClient.Update(context.Background(), &cert)).To(Succeed())

			By("grabbing the new secret")
			var secret corev1.Secret
			Eventually(func() error { return f.CRClient.Get(context.Background(), secretName, &secret) }, "10s", "2s").Should(Succeed())

			By("verifying that the hooks have the new data")
			caData := secret.Data["ca.crt"]
			Eventually(func() ([][]byte, error) {
				var newHook admissionreg.ValidatingWebhookConfiguration
				if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: hook.Name}, &newHook); err != nil {
					return nil, err
				}
				return [][]byte{newHook.Webhooks[0].ClientConfig.CABundle, newHook.Webhooks[1].ClientConfig.CABundle}, nil
			}, "10s", "2s").Should(Equal([][]byte{caData, caData}))
		})

		It("should ignore webhooks with invalid annotations", func() {
			By("creating a validating webhook with an invalid cert name")
			someURL := "https://localhost:8675"
			hook := admissionreg.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-hook",
					Annotations: map[string]string{
						injctrl.WantInjectAnnotation: "serving-certs",
					},
				},
				Webhooks: []admissionreg.Webhook{
					{
						Name: "hook1.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							URL:      &someURL,
							CABundle: []byte("ca data 1"),
						},
					},
					{
						Name: "hook2.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							Service: &admissionreg.ServiceReference{
								Name:      "some-svc",
								Namespace: f.Namespace.Name,
							},
							CABundle: []byte("ca data 2"),
						},
					},
				},
			}
			Expect(f.CRClient.Create(context.Background(), &hook)).To(Succeed())
			hookToCleanUp = &hook

			By("expecting the CA data to remain in place")
			Consistently(func() ([][]byte, error) {
				var newHook admissionreg.ValidatingWebhookConfiguration
				if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: hook.Name}, &newHook); err != nil {
					return nil, err
				}
				return [][]byte{newHook.Webhooks[0].ClientConfig.CABundle, newHook.Webhooks[1].ClientConfig.CABundle}, nil
			}).Should(Equal([][]byte{hook.Webhooks[0].ClientConfig.CABundle, hook.Webhooks[1].ClientConfig.CABundle}))

		})

		It("should inject the apiserver CA if the webhook as the inject-apiserver-ca annotation", func() {
			if len(f.KubeClientConfig.CAData) == 0 {
				Skip("skipping test as the kube client CA bundle is not set")
			}
			By("creating a vaidating webhook with the inject-apiserver-ca annotation")
			someURL := "https://localhost:8675"
			hook := admissionreg.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "apiserver-ca-hook",
					Annotations: map[string]string{
						injctrl.WantInjectAPIServerCAAnnotation: "true",
					},
				},
				Webhooks: []admissionreg.Webhook{
					{
						Name: "hook1.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							URL: &someURL,
						},
					},
					{
						Name: "hook2.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							Service: &admissionreg.ServiceReference{
								Name:      "some-svc",
								Namespace: f.Namespace.Name,
							},
						},
					},
				},
			}
			Expect(f.CRClient.Create(context.Background(), &hook)).To(Succeed())
			hookToCleanUp = &hook

			By("checking that all webhooks have a populated CA")
			caData := f.KubeClientConfig.CAData
			Eventually(func() ([][]byte, error) {
				var newHook admissionreg.ValidatingWebhookConfiguration
				if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: hook.Name}, &newHook); err != nil {
					return nil, err
				}
				return [][]byte{newHook.Webhooks[0].ClientConfig.CABundle, newHook.Webhooks[1].ClientConfig.CABundle}, nil
			}, "10s", "2s").Should(Equal([][]byte{caData, caData}))
		})
	})
})
