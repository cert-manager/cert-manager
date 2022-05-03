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

package certificates

import (
	"bytes"
	"context"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	e2eutil "github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	applycorev1 "k8s.io/client-go/applyconfigurations/core/v1"
)

// This test ensures that the Certificates SecretTemplate is reflected on the
// Certificate's target Secret, and is reconciled on modify events.
var _ = framework.CertManagerDescribe("Certificate SecretTemplate", func() {
	const (
		issuerName   = "certificate-secret-template"
		secretName   = "test-secret-template"
		fieldManager = "e2e-test-field-manager"
	)

	f := framework.NewDefaultFramework("certificates-secret-template")

	createCertificate := func(f *framework.Framework, secretTemplate *cmapi.CertificateSecretTemplate) *cmapi.Certificate {
		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-secret-template-",
				Namespace:    f.Namespace.Name,
			},
			Spec: cmapi.CertificateSpec{
				CommonName: "test",
				SecretName: secretName,
				IssuerRef: cmmeta.ObjectReference{
					Name:  issuerName,
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
				SecretTemplate: secretTemplate,
			},
		}

		By("creating Certificate with SecretTemplate")

		crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(context.Background(), crt, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		crt, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(crt, time.Second*30)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		return crt
	}

	BeforeEach(func() {
		By("creating a self-signing issuer")
		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}))
		Expect(f.CRClient.Create(context.Background(), issuer)).To(Succeed())

		By("Waiting for Issuer to become Ready")
		err := e2eutil.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName, cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.Background(), issuerName, metav1.DeleteOptions{})).NotTo(HaveOccurred())
	})

	It("should not remove Annotations and Labels which have been added by a third party and not present in the SecretTemplate", func() {
		createCertificate(f, &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}})

		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("ensure Secret has correct Labels and Annotations with SecretTemplate")
		Expect(secret.Annotations).To(HaveKeyWithValue("foo", "bar"))
		Expect(secret.Labels).To(HaveKeyWithValue("abc", "123"))

		By("add Annotation to Secret which should not be removed")
		applyConfig, err := applycorev1.ExtractSecret(secret, fieldManager)
		Expect(err).NotTo(HaveOccurred())
		applyConfig = applyConfig.WithAnnotations(map[string]string{"random": "annotation"})

		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Apply(context.Background(), applyConfig, metav1.ApplyOptions{FieldManager: fieldManager})
		Expect(err).NotTo(HaveOccurred())

		Consistently(func() map[string]string {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Annotations
		}, "20s", "1s").Should(HaveKeyWithValue("foo", "bar"))
		Expect(secret.Annotations).To(HaveKeyWithValue("random", "annotation"))

		By("add Label to Secret which should not be removed")

		applyConfig, err = applycorev1.ExtractSecret(secret, fieldManager)
		Expect(err).NotTo(HaveOccurred())
		applyConfig = applyConfig.WithLabels(map[string]string{"random": "label"})
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Apply(context.Background(), applyConfig, metav1.ApplyOptions{FieldManager: fieldManager})
		Expect(err).NotTo(HaveOccurred())

		Consistently(func() map[string]string {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Labels
		}, "20s", "1s").Should(HaveKeyWithValue("abc", "123"))
	})

	It("should add Annotations and Labels to the Secret when the Certificate's SecretTemplate is updated, then remove Annotations and Labels when removed from the SecretTemplate", func() {
		crt := createCertificate(f, &cmapi.CertificateSecretTemplate{
			Annotations: map[string]string{"foo": "bar", "bar": "foo"},
			Labels:      map[string]string{"abc": "123", "def": "456"},
		})

		By("ensure Secret has correct Labels and Annotations with SecretTemplate")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(secret.Annotations).To(HaveKeyWithValue("foo", "bar"))
		Expect(secret.Annotations).To(HaveKeyWithValue("bar", "foo"))
		Expect(secret.Labels).To(HaveKeyWithValue("abc", "123"))
		Expect(secret.Labels).To(HaveKeyWithValue("def", "456"))

		By("adding Annotations and Labels to SecretTemplate should appear on the Secret")

		crt.Spec.SecretTemplate.Annotations["random"] = "annotation"
		crt.Spec.SecretTemplate.Annotations["another"] = "random annotation"
		crt.Spec.SecretTemplate.Labels["hello"] = "world"
		crt.Spec.SecretTemplate.Labels["random"] = "label"

		crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() map[string]string {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Annotations
		}, "20s", "1s").Should(HaveKeyWithValue("random", "annotation"))
		Expect(secret.Annotations).To(HaveKeyWithValue("bar", "foo"))
		Expect(secret.Annotations).To(HaveKeyWithValue("foo", "bar"))
		Expect(secret.Annotations).To(HaveKeyWithValue("another", "random annotation"))

		Eventually(func() map[string]string {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Labels
		}, "20s", "1s").Should(HaveKeyWithValue("hello", "world"))
		Expect(secret.Labels).To(HaveKeyWithValue("def", "456"))
		Expect(secret.Labels).To(HaveKeyWithValue("abc", "123"))
		Expect(secret.Labels).To(HaveKeyWithValue("random", "label"))

		By("removing Annotations and Labels in SecretTemplate should get removed on the Secret")

		crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(context.Background(), crt.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		delete(crt.Spec.SecretTemplate.Annotations, "foo")
		delete(crt.Spec.SecretTemplate.Annotations, "random")
		delete(crt.Spec.SecretTemplate.Labels, "abc")
		delete(crt.Spec.SecretTemplate.Labels, "another")

		_, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() map[string]string {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Annotations
		}, "20s", "1s").ShouldNot(HaveKey("foo"))

		Expect(secret.Annotations).ToNot(HaveKey("random"))
		Expect(secret.Labels).ToNot(HaveKey("abc"))
		Expect(secret.Labels).ToNot(HaveKey("another"))
	})

	It("should update the values of keys that have been modified in the SecretTemplate", func() {
		crt := createCertificate(f, &cmapi.CertificateSecretTemplate{
			Annotations: map[string]string{"foo": "bar", "bar": "foo"},
			Labels:      map[string]string{"abc": "123", "def": "456"},
		})

		By("ensure Secret has correct Labels and Annotations with SecretTemplate")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		Expect(secret.Annotations).To(HaveKeyWithValue("foo", "bar"))
		Expect(secret.Annotations).To(HaveKeyWithValue("bar", "foo"))
		Expect(secret.Labels).To(HaveKeyWithValue("abc", "123"))
		Expect(secret.Labels).To(HaveKeyWithValue("def", "456"))

		By("changing Annotation and Label keys on the SecretTemplate should be reflected on the Secret")

		crt.Spec.SecretTemplate.Annotations["foo"] = "123"
		crt.Spec.SecretTemplate.Annotations["bar"] = "not foo"
		crt.Spec.SecretTemplate.Labels["abc"] = "098"
		crt.Spec.SecretTemplate.Labels["def"] = "555"

		_, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() map[string]string {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Annotations
		}, "20s", "1s").Should(HaveKeyWithValue("foo", "123"))
		Expect(secret.Annotations).To(HaveKeyWithValue("bar", "not foo"))
		Expect(secret.Labels).To(HaveKeyWithValue("abc", "098"))
		Expect(secret.Labels).To(HaveKeyWithValue("def", "555"))
	})

	It("should add cert-manager manager to existing Annotation and Labels fields which are added to SecretTemplate, should not be removed if they are removed by the third party", func() {
		By("Secret Annotations and Labels should not be removed if the field still hold a field manager")

		crt := createCertificate(f, nil)

		By("add Labels and Annotations to the Secret that are not owned by cert-manager")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		applyconfig, err := applycorev1.ExtractSecret(secret, fieldManager)
		Expect(err).NotTo(HaveOccurred())

		annots := map[string]string{
			"an-annotation":      "bar",
			"another-annotation": "def",
		}
		labels := map[string]string{
			"abc": "123",
			"foo": "bar",
		}
		applyconfig = applyconfig.WithAnnotations(annots)
		applyconfig = applyconfig.WithLabels(labels)
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Apply(context.Background(), applyconfig, metav1.ApplyOptions{FieldManager: fieldManager})
		Expect(err).ToNot(HaveOccurred())

		By("expect those Annotations and Labels to be present on the Secret")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(secret.Annotations).To(HaveKeyWithValue("an-annotation", "bar"))
		Expect(secret.Annotations).To(HaveKeyWithValue("another-annotation", "def"))
		Expect(secret.Labels).To(HaveKeyWithValue("abc", "123"))
		Expect(secret.Labels).To(HaveKeyWithValue("foo", "bar"))

		By("add those Annotations and Labels to the SecretTemplate of the Certificate")
		crt.Spec.SecretTemplate = &cmapi.CertificateSecretTemplate{
			Annotations: map[string]string{"an-annotation": "bar", "another-annotation": "def"},
			Labels:      map[string]string{"abc": "123", "foo": "bar"},
		}

		_, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for those Annotation and Labels on the Secret to contain managed fields from cert-manager")

		Eventually(func() bool {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			var managedLabels, managedAnnotations []string
			for _, managedField := range secret.ManagedFields {
				// The field manager of the issuing controller is currently
				// "cert-manager-certificates-issuing".
				if managedField.Manager != "cert-manager-certificates-issuing" || managedField.FieldsV1 == nil {
					continue
				}

				var fieldset fieldpath.Set
				if err := fieldset.FromJSON(bytes.NewReader(managedField.FieldsV1.Raw)); err != nil {
					Expect(err).NotTo(HaveOccurred())
				}

				metadata := fieldset.Children.Descend(fieldpath.PathElement{
					FieldName: pointer.String("metadata"),
				})
				labels := metadata.Children.Descend(fieldpath.PathElement{
					FieldName: pointer.String("labels"),
				})
				annotations := metadata.Children.Descend(fieldpath.PathElement{
					FieldName: pointer.String("annotations"),
				})

				labels.Iterate(func(path fieldpath.Path) {
					managedLabels = append(managedLabels, strings.TrimPrefix(path.String(), "."))
				})
				annotations.Iterate(func(path fieldpath.Path) {
					managedAnnotations = append(managedAnnotations, strings.TrimPrefix(path.String(), "."))
				})
			}

			for _, expectedAnnoation := range []string{"an-annotation", "another-annotation"} {
				var found bool
				for _, managedAnnotation := range managedAnnotations {
					if expectedAnnoation == managedAnnotation {
						found = true
						break
					}
				}

				if !found {
					return false
				}
			}

			for _, expectedLabel := range []string{"abc", "foo"} {
				var found bool
				for _, managedLabel := range managedLabels {
					if expectedLabel == managedLabel {
						found = true
						break
					}
				}

				if !found {
					return false
				}
			}

			return true
		}, "20s", "1s").Should(BeTrue())

		By("removing Annotation and Labels from by third party client should not remove them as they are also managed by cert-manager")

		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Apply(context.Background(),
			applycorev1.Secret(secret.Name, secret.Namespace).
				WithAnnotations(make(map[string]string)).
				WithLabels(make(map[string]string)),
			metav1.ApplyOptions{FieldManager: fieldManager})

		Consistently(func() map[string]string {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Annotations
		}, "20s", "1s").Should(HaveKeyWithValue("an-annotation", "bar"))
		Expect(secret.Annotations).To(HaveKeyWithValue("another-annotation", "def"))
		Expect(secret.Labels).To(HaveKeyWithValue("abc", "123"))
		Expect(secret.Labels).To(HaveKeyWithValue("foo", "bar"))
	})

	It("if data keys are added to the Secret, they should not be removed", func() {
		createCertificate(f, &cmapi.CertificateSecretTemplate{
			Annotations: map[string]string{"abc": "123"},
			Labels:      map[string]string{"foo": "bar"},
		})

		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		applyConfig, err := applycorev1.ExtractSecret(secret, fieldManager)
		Expect(err).NotTo(HaveOccurred())
		applyConfig = applyConfig.WithData(map[string][]byte{"random-key": []byte("hello-world")})
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Apply(context.Background(), applyConfig, metav1.ApplyOptions{FieldManager: fieldManager})
		Expect(err).NotTo(HaveOccurred())

		Consistently(func() map[string][]byte {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Data
		}, "20s", "1s").Should(HaveKeyWithValue("random-key", []byte("hello-world")))
	})

	It("if values are modified on the Certificate's SecretTemplate, than those values should be reflected on the Secret", func() {
		crt := createCertificate(f, &cmapi.CertificateSecretTemplate{
			Annotations: map[string]string{"abc": "123"},
			Labels:      map[string]string{"foo": "bar"},
		})
		crt.Spec.SecretTemplate.Annotations["abc"] = "456"
		crt.Spec.SecretTemplate.Labels["foo"] = "foo"

		_, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() map[string]string {
			secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Annotations
		}, "20s", "1s").Should(HaveKeyWithValue("abc", "456"))

		Eventually(func() map[string]string {
			secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Labels
		}, "20s", "1s").Should(HaveKeyWithValue("foo", "foo"))
	})

	It("deleting a Certificate's SecretTemplate should remove all keys it defined", func() {
		crt := createCertificate(f, &cmapi.CertificateSecretTemplate{
			Annotations: map[string]string{"abc": "123", "def": "456"},
			Labels:      map[string]string{"foo": "bar", "label": "hello-world"},
		})

		var (
			secret *corev1.Secret
			err    error
		)
		Eventually(func() map[string]string {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Annotations
		}, "20s", "1s").Should(HaveKeyWithValue("abc", "123"))
		Expect(secret.Annotations).To(HaveKeyWithValue("def", "456"))
		Expect(secret.Labels).To(HaveKeyWithValue("foo", "bar"))
		Expect(secret.Labels).To(HaveKeyWithValue("label", "hello-world"))

		crt.Spec.SecretTemplate = nil

		_, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() map[string]string {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Annotations
		}, "20s", "1s").ShouldNot(HaveKey("abc"))
		Expect(secret.Annotations).ToNot(HaveKey("def"))
		Expect(secret.Labels).ToNot(HaveKey("foo"))
		Expect(secret.Labels).ToNot(HaveKey("label"))
	})
})
