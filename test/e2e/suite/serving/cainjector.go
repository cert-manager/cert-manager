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
	"fmt"
	"time"

	admissionreg "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/util"
	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type injectableTest struct {
	makeInjectable func(namePrefix string) client.Object
	getCAs         func(runtime.Object) [][]byte
	disabled       string
}

var _ = framework.CertManagerDescribe("CA Injector", func() {
	f := framework.NewDefaultFramework("cainjector")
	ctx := context.TODO()

	issuerName := "inject-cert-issuer"
	secretName := "serving-certs-data"

	injectorContext := func(subj string, test *injectableTest) {
		Context("for "+subj+"s", func() {
			var toCleanup client.Object

			BeforeEach(func() {
				By("creating a self-signing issuer")
				issuer := gen.Issuer(issuerName,
					gen.SetIssuerNamespace(f.Namespace.Name),
					gen.SetIssuerSelfSigned(v1.SelfSignedIssuer{}))
				Expect(f.CRClient.Create(context.Background(), issuer)).To(Succeed())

				By("Waiting for Issuer to become Ready")
				err := util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
					issuerName,
					certmanager.IssuerCondition{
						Type:   certmanager.IssuerConditionReady,
						Status: cmmeta.ConditionTrue,
					})
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				if toCleanup == nil {
					return
				}
				Expect(f.CRClient.Delete(context.Background(), toCleanup)).To(Succeed())
			})
			generalSetup := func(injectable client.Object) (runtime.Object, *certmanager.Certificate) {
				By("creating a " + subj + " pointing to a cert")
				Expect(f.CRClient.Create(context.Background(), injectable)).To(Succeed())
				toCleanup = injectable

				By("creating a certificate")
				secretName := types.NamespacedName{Name: secretName, Namespace: f.Namespace.Name}
				cert := gen.Certificate("serving-certs",
					gen.SetCertificateNamespace(f.Namespace.Name),
					gen.SetCertificateSecretName(secretName.Name),
					gen.SetCertificateIssuer(cmmeta.ObjectReference{
						Name: issuerName,
						Kind: certmanager.IssuerKind,
					}),
					gen.SetCertificateCommonName("test.domain.com"),
					gen.SetCertificateOrganization("test-org"),
				)
				Expect(f.CRClient.Create(context.Background(), cert)).To(Succeed())

				cert, err := f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*2)
				Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

				By("grabbing the corresponding secret")
				var secret corev1.Secret
				Expect(f.CRClient.Get(context.Background(), secretName, &secret)).To(Succeed())

				By("checking that all webhooks have a populated CA")
				caData := secret.Data["ca.crt"]
				expectedLen := len(test.getCAs(injectable))
				expectedCAs := make([][]byte, expectedLen)
				for i := range expectedCAs {
					expectedCAs[i] = caData
				}
				Eventually(func() ([][]byte, error) {
					newInjectable := injectable.DeepCopyObject().(client.Object)
					if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: injectable.(metav1.Object).GetName()}, newInjectable); err != nil {
						return nil, err
					}
					return test.getCAs(newInjectable), nil
				}, "10s", "2s").Should(Equal(expectedCAs))

				return injectable, cert
			}

			It("should inject the CA data into all CA fields", func() {
				if test.disabled != "" {
					Skip(test.disabled)
				}

				generalSetup(test.makeInjectable("injected"))
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
					newInjectable := injectable.DeepCopyObject().(client.Object)
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
				injectable, cert := generalSetup(test.makeInjectable("changed"))

				By("changing the name of the corresponding secret in the cert")
				retry.RetryOnConflict(retry.DefaultRetry, func() error {
					err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: cert.Name, Namespace: cert.Namespace}, cert)
					if err != nil {
						return err
					}

					cert.Spec.DNSNames = append(cert.Spec.DNSNames, "something.com")

					err = f.CRClient.Update(context.Background(), cert)
					if err != nil {
						return err
					}
					return nil
				})

				cert, err := f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*2)
				Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become updated")

				By("grabbing the new secret")
				var secret corev1.Secret
				secretName := types.NamespacedName{Name: cert.Spec.SecretName, Namespace: f.Namespace.Name}
				Expect(f.CRClient.Get(context.Background(), secretName, &secret)).To(Succeed())

				By("verifying that the hooks have the new data")
				caData := secret.Data["ca.crt"]
				expectedLen := len(test.getCAs(injectable))
				expectedCAs := make([][]byte, expectedLen)
				for i := range expectedCAs {
					expectedCAs[i] = caData
				}
				Eventually(func() ([][]byte, error) {
					newInjectable := injectable.DeepCopyObject().(client.Object)
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
					certmanager.WantInjectAnnotation: "serving-certs", // an invalid annotation
				})
				Expect(f.CRClient.Create(context.Background(), injectable)).To(Succeed())
				toCleanup = injectable

				By("expecting the CA data to remain in place")
				expectedCAs := test.getCAs(injectable)
				Consistently(func() ([][]byte, error) {
					newInjectable := injectable.DeepCopyObject().(client.Object)
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
				By("creating an injectable with the inject-apiserver-ca annotation")
				injectable := test.makeInjectable("apiserver-ca")
				injectable.(metav1.Object).SetAnnotations(map[string]string{
					certmanager.WantInjectAPIServerCAAnnotation: "true",
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
					newInjectable := injectable.DeepCopyObject().(client.Object)
					if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: injectable.(metav1.Object).GetName()}, newInjectable); err != nil {
						return nil, err
					}
					return test.getCAs(newInjectable), nil
				}, "1m", "2s").Should(Equal(expectedCAs))
			})

			It("should inject a CA directly from a secret if the inject-ca-from-secret annotation is present", func() {
				if test.disabled != "" {
					Skip(test.disabled)
				}
				secretName := types.NamespacedName{Name: secretName, Namespace: f.Namespace.Name}
				annotatedSecret := corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName.Name,
						Namespace: secretName.Namespace,
						Annotations: map[string]string{
							certmanager.AllowsInjectionFromSecretAnnotation: "true",
						},
					},
				}
				Expect(f.CRClient.Create(context.Background(), &annotatedSecret)).To(Succeed())

				injectable := test.makeInjectable("from-secret")
				injectable.(metav1.Object).SetAnnotations(map[string]string{
					certmanager.WantInjectFromSecretAnnotation: secretName.String(),
				})
				generalSetup(injectable)
			})

			It("should refuse to inject a CA directly from a secret if the allow-direct-injection annotation is not 'true'", func() {
				if test.disabled != "" {
					Skip(test.disabled)
				}
				secretName := types.NamespacedName{Name: secretName, Namespace: f.Namespace.Name}
				annotatedSecret := corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName.Name,
						Namespace: secretName.Namespace,
						Annotations: map[string]string{
							certmanager.AllowsInjectionFromSecretAnnotation: "false",
						},
					},
				}
				Expect(f.CRClient.Create(context.Background(), &annotatedSecret)).To(Succeed())

				By("creating a " + subj + " pointing to a secret")
				injectable := test.makeInjectable("from-secret-not-allowed")
				injectable.(metav1.Object).SetAnnotations(map[string]string{
					certmanager.WantInjectFromSecretAnnotation: secretName.String(),
				})
				Expect(f.CRClient.Create(context.Background(), injectable)).To(Succeed())
				toCleanup = injectable

				By("creating a certificate")
				cert := gen.Certificate("serving-certs",
					gen.SetCertificateNamespace(f.Namespace.Name),
					gen.SetCertificateSecretName(secretName.Name),
					gen.SetCertificateIssuer(cmmeta.ObjectReference{
						Name: issuerName,
						Kind: certmanager.IssuerKind,
					}),
					gen.SetCertificateCommonName("test.domain.com"),
					gen.SetCertificateOrganization("test-org"),
				)
				Expect(f.CRClient.Create(context.Background(), cert)).To(Succeed())

				By("grabbing the corresponding secret")
				var secret corev1.Secret
				Eventually(func() error { return f.CRClient.Get(context.Background(), secretName, &secret) }, "30s", "2s").Should(Succeed())

				By("checking that all webhooks have an empty CA")
				expectedLen := len(test.getCAs(injectable))
				expectedCAs := make([][]byte, expectedLen)
				for i := range expectedCAs {
					expectedCAs[i] = nil
				}
				Consistently(func() ([][]byte, error) {
					newInjectable := injectable.DeepCopyObject().(client.Object)
					if err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: injectable.(metav1.Object).GetName()}, newInjectable); err != nil {
						return nil, err
					}
					return test.getCAs(newInjectable), nil
				}, "30s", "2s").Should(Equal(expectedCAs))
			})
		})
	}

	sideEffectsNone := admissionreg.SideEffectClassNone

	injectorContext("validating webhook", &injectableTest{
		makeInjectable: func(namePrefix string) client.Object {
			someURL := "https://localhost:8675"
			return &admissionreg.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: fmt.Sprintf("%s-hook", namePrefix),
					Annotations: map[string]string{
						certmanager.WantInjectAnnotation: types.NamespacedName{Name: "serving-certs", Namespace: f.Namespace.Name}.String(),
					},
				},
				Webhooks: []admissionreg.ValidatingWebhook{
					{
						Name: "hook1.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							URL: &someURL,
						},
						SideEffects:             &sideEffectsNone,
						AdmissionReviewVersions: []string{"v1beta1"},
					},
					{
						Name: "hook2.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							Service: &admissionreg.ServiceReference{
								Name:      "some-svc",
								Namespace: f.Namespace.Name,
							},
						},
						SideEffects:             &sideEffectsNone,
						AdmissionReviewVersions: []string{"v1beta1"},
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
		makeInjectable: func(namePrefix string) client.Object {
			someURL := "https://localhost:8675"
			return &admissionreg.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: fmt.Sprintf("%s-hook", namePrefix),
					Annotations: map[string]string{
						certmanager.WantInjectAnnotation: types.NamespacedName{Name: "serving-certs", Namespace: f.Namespace.Name}.String(),
					},
				},
				Webhooks: []admissionreg.MutatingWebhook{
					{
						Name: "hook1.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							URL: &someURL,
						},
						SideEffects:             &sideEffectsNone,
						AdmissionReviewVersions: []string{"v1beta1"},
					},
					{
						Name: "hook2.fake.k8s.io",
						ClientConfig: admissionreg.WebhookClientConfig{
							Service: &admissionreg.ServiceReference{
								Name:      "some-svc",
								Namespace: f.Namespace.Name,
							},
						},
						SideEffects:             &sideEffectsNone,
						AdmissionReviewVersions: []string{"v1beta1"},
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
		makeInjectable: func(namePrefix string) client.Object {
			someURL := "https://localhost:8675"
			return &apiext.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "objs." + namePrefix + ".testing.cert-manager.io",
					Annotations: map[string]string{
						certmanager.WantInjectAnnotation: types.NamespacedName{Name: "serving-certs", Namespace: f.Namespace.Name}.String(),
					},
				},
				Spec: apiext.CustomResourceDefinitionSpec{
					Group: namePrefix + ".testing.cert-manager.io",
					Versions: []apiext.CustomResourceDefinitionVersion{
						{
							Name: "v1",
						},
					},
					Conversion: &apiext.CustomResourceConversion{
						Strategy: apiext.WebhookConverter,
						Webhook: &apiext.WebhookConversion{
							ClientConfig: &apiext.WebhookClientConfig{
								URL: &someURL,
							},
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
			if crd.Spec.Conversion == nil || crd.Spec.Conversion.Webhook == nil || crd.Spec.Conversion.Webhook.ClientConfig == nil {
				return nil
			}
			return [][]byte{crd.Spec.Conversion.Webhook.ClientConfig.CABundle}
		},
		disabled: "ConversionWebhook feature not yet enabled on test infra",
	})

	injectorContext("api service", &injectableTest{
		makeInjectable: func(namePrefix string) client.Object {
			return &apireg.APIService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "v1." + namePrefix + ".testing.cert-manager.io",
					Annotations: map[string]string{
						certmanager.WantInjectAnnotation: types.NamespacedName{Name: "serving-certs", Namespace: f.Namespace.Name}.String(),
					},
				},
				Spec: apireg.APIServiceSpec{
					Service: &apireg.ServiceReference{
						Name:      "does-not-exit",
						Namespace: "default",
					},
					Group:                namePrefix + ".testing.cert-manager.io",
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
