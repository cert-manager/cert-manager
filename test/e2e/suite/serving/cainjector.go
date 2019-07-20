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
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

type injectableTest struct {
	makeInjectable func(namePrefix string) runtime.Object
	getCAs         func(runtime.Object) [][]byte
	subject        string
	disabled       string
}

var _ = framework.CertManagerDescribe("CA Injector", func() {
	f := framework.NewDefaultFramework("ca-injector")

	issuerName := "inject-cert-issuer"

	injectorContext := func(subj string, test *injectableTest) {
		Context("for "+subj+"s", func() {
			var toCleanup runtime.Object

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
				if toCleanup == nil {
					return
				}
				Expect(f.CRClient.Delete(context.Background(), toCleanup)).To(Succeed())
			})
			generalSetup := func(namePrefix string) (runtime.Object, certmanager.Certificate, corev1.Secret) {
				By("creating a " + subj + " pointing to a cert")
				injectable := test.makeInjectable(namePrefix)
				Expect(f.CRClient.Create(context.Background(), injectable)).To(Succeed())
				toCleanup = injectable

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
				expectedLen := len(test.getCAs(injectable))
				expectedCAs := make([][]byte, expectedLen)
				for i := range expectedCAs {
					expectedCAs[i] = caData
				}
				Eventually(func() ([][]byte, error) {
					newInjectable := injectable.DeepCopyObject()
					if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: injectable.(metav1.Object).GetName()}, newInjectable); err != nil {
						return nil, err
					}
					return test.getCAs(newInjectable), nil
				}, "10s", "2s").Should(Equal(expectedCAs))

				return injectable, *cert, secret

			}

			It("should inject the CA data into all CA fields", func() {
				if test.disabled != "" {
					Skip(test.disabled)
				}

				generalSetup("injected")
			})

			It("should not inject CA into non-annotated objects", func() {
				if test.disabled != "" {
					Skip(test.disabled)
				}
				By("creating a validating webhook not pointing to a cert")
				injectable := test.makeInjectable("non-injected")
				injectable.(metav1.Object).SetAnnotations(map[string]string{}) // wipe out the inject annotation
				Expect(f.CRClient.Create(context.Background(), injectable)).To(Succeed())
				toCleanup = injectable

				By("expecting the CA data to remain in place")
				expectedCAs := test.getCAs(injectable)
				Consistently(func() ([][]byte, error) {
					newInjectable := injectable.DeepCopyObject()
					if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: injectable.(metav1.Object).GetName()}, newInjectable); err != nil {
						return nil, err
					}
					return test.getCAs(newInjectable), nil
				}).Should(Equal(expectedCAs))
			})

			It("should update data when the certificate changes", func() {
				if test.disabled != "" {
					Skip(test.disabled)
				}
				injectable, cert, _ := generalSetup("changed")

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
				expectedLen := len(test.getCAs(injectable))
				expectedCAs := make([][]byte, expectedLen)
				for i := range expectedCAs {
					expectedCAs[i] = caData
				}
				Eventually(func() ([][]byte, error) {
					newInjectable := injectable.DeepCopyObject()
					if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: injectable.(metav1.Object).GetName()}, newInjectable); err != nil {
						return nil, err
					}
					return test.getCAs(newInjectable), nil
				}, "10s", "2s").Should(Equal(expectedCAs))
			})

			It("should ignore objects with invalid annotations", func() {
				if test.disabled != "" {
					Skip(test.disabled)
				}
				By("creating a validating webhook with an invalid cert name")
				injectable := test.makeInjectable("invalid")
				injectable.(metav1.Object).SetAnnotations(map[string]string{
					injctrl.WantInjectAnnotation: "serving-certs", // an invalid annotation
				})
				Expect(f.CRClient.Create(context.Background(), injectable)).To(Succeed())
				toCleanup = injectable

				By("expecting the CA data to remain in place")
				expectedCAs := test.getCAs(injectable)
				Consistently(func() ([][]byte, error) {
					newInjectable := injectable.DeepCopyObject()
					if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: injectable.(metav1.Object).GetName()}, newInjectable); err != nil {
						return nil, err
					}
					return test.getCAs(newInjectable), nil
				}).Should(Equal(expectedCAs))
			})

			It("should inject the apiserver CA if the inject-apiserver-ca annotation is present", func() {
				if test.disabled != "" {
					Skip(test.disabled)
				}
				if len(f.KubeClientConfig.CAData) == 0 {
					Skip("skipping test as the kube client CA bundle is not set")
				}
				By("creating a vaidating webhook with the inject-apiserver-ca annotation")
				injectable := test.makeInjectable("apiserver-ca")
				injectable.(metav1.Object).SetAnnotations(map[string]string{
					injctrl.WantInjectAPIServerCAAnnotation: "true",
				})
				Expect(f.CRClient.Create(context.Background(), injectable)).To(Succeed())
				toCleanup = injectable

				By("checking that all webhooks have a populated CA")
				caData := f.KubeClientConfig.CAData
				expectedLen := len(test.getCAs(injectable))
				expectedCAs := make([][]byte, expectedLen)
				for i := range expectedCAs {
					expectedCAs[i] = caData
				}
				Eventually(func() ([][]byte, error) {
					newInjectable := injectable.DeepCopyObject()
					if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: injectable.(metav1.Object).GetName()}, newInjectable); err != nil {
						return nil, err
					}
					return test.getCAs(newInjectable), nil
				}, "10s", "2s").Should(Equal(expectedCAs))
			})
		})
	}

	injectorContext("validating webhook", &injectableTest{
		makeInjectable: func(namePrefix string) runtime.Object {
			someURL := "https://localhost:8675"
			return &admissionreg.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: namePrefix + "-hook",
					Annotations: map[string]string{
						injctrl.WantInjectAnnotation: types.NamespacedName{Name: "serving-certs", Namespace: f.Namespace.Name}.String(),
					},
				},
				Webhooks: []admissionreg.ValidatingWebhook{
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
		},
		getCAs: func(obj runtime.Object) [][]byte {
			hook := obj.(*admissionreg.ValidatingWebhookConfiguration)
			res := make([][]byte, len(hook.Webhooks))
			for i, webhook := range hook.Webhooks {
				res[i] = webhook.ClientConfig.CABundle
			}
			return res
		},
	})

	injectorContext("mutating webhook", &injectableTest{
		makeInjectable: func(namePrefix string) runtime.Object {
			someURL := "https://localhost:8675"
			return &admissionreg.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: namePrefix + "-hook",
					Annotations: map[string]string{
						injctrl.WantInjectAnnotation: types.NamespacedName{Name: "serving-certs", Namespace: f.Namespace.Name}.String(),
					},
				},
				Webhooks: []admissionreg.MutatingWebhook{
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
		},
		getCAs: func(obj runtime.Object) [][]byte {
			hook := obj.(*admissionreg.MutatingWebhookConfiguration)
			res := make([][]byte, len(hook.Webhooks))
			for i, webhook := range hook.Webhooks {
				res[i] = webhook.ClientConfig.CABundle
			}
			return res
		},
	})

	// TODO(directxman12): enable ConversionWebhook feature on the test infra,
	// re-enable this.
	injectorContext("conversion webhook", &injectableTest{
		makeInjectable: func(namePrefix string) runtime.Object {
			someURL := "https://localhost:8675"
			return &apiext.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "objs." + namePrefix + ".testing.certmanager.k8s.io",
					Annotations: map[string]string{
						injctrl.WantInjectAnnotation: types.NamespacedName{Name: "serving-certs", Namespace: f.Namespace.Name}.String(),
					},
				},
				Spec: apiext.CustomResourceDefinitionSpec{
					Group:   namePrefix + ".testing.certmanager.k8s.io",
					Version: "v1",
					Conversion: &apiext.CustomResourceConversion{
						Strategy: apiext.WebhookConverter,
						WebhookClientConfig: &apiext.WebhookClientConfig{
							URL: &someURL,
						},
					},
					Names: apiext.CustomResourceDefinitionNames{
						Kind:     "Obj",
						ListKind: "ObjList",
					},
				},
			}
		},
		getCAs: func(obj runtime.Object) [][]byte {
			crd := obj.(*apiext.CustomResourceDefinition)
			if crd.Spec.Conversion == nil || crd.Spec.Conversion.WebhookClientConfig == nil {
				return nil
			}
			return [][]byte{crd.Spec.Conversion.WebhookClientConfig.CABundle}
		},
		disabled: "ConversionWebhook feature not yet enabled on test infra",
	})

	injectorContext("api service", &injectableTest{
		makeInjectable: func(namePrefix string) runtime.Object {
			return &apireg.APIService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "v1." + namePrefix + ".testing.certmanager.k8s.io",
					Annotations: map[string]string{
						injctrl.WantInjectAnnotation: types.NamespacedName{Name: "serving-certs", Namespace: f.Namespace.Name}.String(),
					},
				},
				Spec: apireg.APIServiceSpec{
					Service: &apireg.ServiceReference{
						Name:      "does-not-exit",
						Namespace: "default",
					},
					Group:                namePrefix + ".testing.certmanager.k8s.io",
					Version:              "v1",
					GroupPriorityMinimum: 1,
					VersionPriority:      1,
				},
			}
		},
		getCAs: func(obj runtime.Object) [][]byte {
			apiSvc := obj.(*apireg.APIService)
			return [][]byte{apiSvc.Spec.CABundle}
		},
	})
})
