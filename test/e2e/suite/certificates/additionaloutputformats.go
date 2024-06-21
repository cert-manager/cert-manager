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
	"encoding/pem"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

// This test ensures that the Certificates AdditionalCertificateOutputFormats
// is reflected on the Certificate's target Secret, and is reconciled on modify
// events.
var _ = framework.CertManagerDescribe("Certificate AdditionalCertificateOutputFormats", func() {
	const (
		issuerName = "certificate-additional-output-formats"
		secretName = "test-additional-output-formats"
	)

	ctx := context.TODO()
	f := framework.NewDefaultFramework("certificates-additional-output-formats")

	createCertificate := func(f *framework.Framework, aof []cmapi.CertificateAdditionalOutputFormat) (string, *cmapi.Certificate) {
		framework.RequireFeatureGate(utilfeature.DefaultFeatureGate, feature.AdditionalCertificateOutputFormats)

		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-additional-output-formats-",
				Namespace:    f.Namespace.Name,
			},
			Spec: cmapi.CertificateSpec{
				CommonName: "test",
				SecretName: secretName,
				PrivateKey: &cmapi.CertificatePrivateKey{RotationPolicy: cmapi.RotationPolicyAlways},
				IssuerRef: cmmeta.ObjectReference{
					Name: issuerName, Kind: "Issuer", Group: "cert-manager.io",
				},
				AdditionalOutputFormats: aof,
			},
		}

		By("creating Certificate with AdditionalOutputFormats")
		crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(ctx, crt, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		crt, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, crt, time.Minute*2)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		return crt.Name, crt
	}

	BeforeEach(func() {
		By("creating a self-signing issuer")
		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}))
		Expect(f.CRClient.Create(context.Background(), issuer)).To(Succeed())

		By("Waiting for Issuer to become Ready")
		err := e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName, cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.Background(), issuerName, metav1.DeleteOptions{})).NotTo(HaveOccurred())
	})

	It("should not remove Secret data keys which have been added by a third party, and not present in the Certificate's AdditionalOutputFormats", func() {
		createCertificate(f, nil)

		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("ensure Secret has only expected keys")
		Expect(secret.Data).To(MatchAllKeys(Keys{"tls.crt": Not(BeEmpty()), "tls.key": Not(BeEmpty()), "ca.crt": Not(BeEmpty())}))

		By("add extra Data keys to the secret which should not be removed")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		secret.Data["random-1"] = []byte("data-1")
		secret.Data["random-2"] = []byte("data-2")
		secret.Data["tls-combined.pem"] = []byte("data-3")
		secret.Data["key.der"] = []byte("data-4")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(context.Background(), secret, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		Consistently(func() map[string][]byte {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Data
		}).WithTimeout(5 * time.Second).WithPolling(time.Second).Should(MatchAllKeys(Keys{
			"ca.crt":           Not(BeEmpty()),
			"tls.crt":          Not(BeEmpty()),
			"tls.key":          Not(BeEmpty()),
			"random-1":         Equal([]byte("data-1")),
			"random-2":         Equal([]byte("data-2")),
			"tls-combined.pem": Equal([]byte("data-3")),
			"key.der":          Equal([]byte("data-4")),
		}))
	})

	It("should add additional output formats to the Secret when the Certificate's AdditionalOutputFormats is updated, then removed when removed from AdditionalOutputFormats", func() {
		crtName, crt := createCertificate(f, nil)

		By("ensure Secret has only expected keys")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(secret.Data).To(MatchAllKeys(Keys{
			"ca.crt":  Not(BeEmpty()),
			"tls.crt": Not(BeEmpty()),
			"tls.key": Not(BeEmpty()),
		}))
		crtPEM := secret.Data["tls.crt"]
		pkPEM := secret.Data["tls.key"]
		block, _ := pem.Decode(pkPEM)

		By("add Combined PEM to Certificate's Additional Output Formats")
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(context.Background(), crtName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			crt.Spec.AdditionalOutputFormats = []cmapi.CertificateAdditionalOutputFormat{{Type: "CombinedPEM"}}
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
			return err
		})
		Expect(err).NotTo(HaveOccurred())

		By("ensure Secret has correct Combined PEM additional output formats")
		Eventually(func() map[string][]byte {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Data
		}).WithTimeout(5 * time.Second).WithPolling(time.Second).Should(MatchAllKeys(Keys{
			"ca.crt":           Not(BeEmpty()),
			"tls.crt":          Not(BeEmpty()),
			"tls.key":          Not(BeEmpty()),
			"tls-combined.pem": Equal(append(append(pkPEM, '\n'), crtPEM...)),
		}))

		By("add DER to Certificate's Additional Output Formats")
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(context.Background(), crtName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			crt.Spec.AdditionalOutputFormats = []cmapi.CertificateAdditionalOutputFormat{{Type: "CombinedPEM"}, {Type: "DER"}}
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
			return err
		})
		Expect(err).NotTo(HaveOccurred())

		By("ensure Secret has correct Combined PEM and DER additional output formats")
		Eventually(func() map[string][]byte {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Data
		}).WithTimeout(5 * time.Second).WithPolling(time.Second).Should(MatchAllKeys(Keys{
			"ca.crt":           Not(BeEmpty()),
			"tls.crt":          Not(BeEmpty()),
			"tls.key":          Not(BeEmpty()),
			"tls-combined.pem": Equal(append(append(pkPEM, '\n'), crtPEM...)),
			"key.der":          Equal(block.Bytes),
		}))

		By("remove Combined PEM from Certificate's Additional Output Formats")
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(context.Background(), crtName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			crt.Spec.AdditionalOutputFormats = []cmapi.CertificateAdditionalOutputFormat{{Type: "DER"}}
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
			return err
		})
		Expect(err).NotTo(HaveOccurred())

		By("ensure Secret has correct DER additional output formats")
		Eventually(func() map[string][]byte {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Data
		}).WithTimeout(5 * time.Second).WithPolling(time.Second).Should(MatchAllKeys(Keys{
			"ca.crt":  Not(BeEmpty()),
			"tls.crt": Not(BeEmpty()),
			"tls.key": Not(BeEmpty()),
			"key.der": Equal(block.Bytes),
		}))

		By("remove DER from Certificate's Additional Output Formats")
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(context.Background(), crtName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			crt.Spec.AdditionalOutputFormats = nil
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
			return err
		})
		Expect(err).NotTo(HaveOccurred())

		By("ensure Secret has no additional output formats")
		Eventually(func() map[string][]byte {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Data
		}).WithTimeout(5 * time.Second).WithPolling(time.Second).Should(MatchAllKeys(Keys{
			"ca.crt":  Not(BeEmpty()),
			"tls.crt": Not(BeEmpty()),
			"tls.key": Not(BeEmpty()),
		}))
	})

	It("should update the values of Additional Output Format keys that have been modified on the Secret", func() {
		createCertificate(f, []cmapi.CertificateAdditionalOutputFormat{{Type: "CombinedPEM"}, {Type: "DER"}})

		By("ensure Secret has only expected keys")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		crtPEM := secret.Data["tls.crt"]
		pkPEM := secret.Data["tls.key"]
		block, _ := pem.Decode(pkPEM)
		Expect(secret.Data).To(MatchAllKeys(Keys{
			"ca.crt":           Not(BeEmpty()),
			"tls.crt":          Not(BeEmpty()),
			"tls.key":          Not(BeEmpty()),
			"tls-combined.pem": Equal(append(append(pkPEM, '\n'), crtPEM...)),
			"key.der":          Equal(block.Bytes),
		}))

		By("changing the values of additional output format keys, should have that value reverted to the correct value")
		secret.Data["tls-combined.pem"] = []byte("random-1")
		secret.Data["key.der"] = []byte("random-2")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(context.Background(), secret, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("wait for those values to be reverted on the Secret")
		Eventually(func() map[string][]byte {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Data
		}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(MatchAllKeys(Keys{
			"ca.crt":           Not(BeEmpty()),
			"tls.crt":          Not(BeEmpty()),
			"tls.key":          Not(BeEmpty()),
			"tls-combined.pem": Equal(append(append(pkPEM, '\n'), crtPEM...)),
			"key.der":          Equal(block.Bytes),
		}))
	})

	It("renewing a Certificate should have output format values reflect the new certificate and private key", func() {
		crtName, crt := createCertificate(f, []cmapi.CertificateAdditionalOutputFormat{{Type: "CombinedPEM"}, {Type: "DER"}})

		By("ensure Secret has only expected keys")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		crtPEM := secret.Data["tls.crt"]
		pkPEM := secret.Data["tls.key"]
		block, _ := pem.Decode(pkPEM)
		Expect(secret.Data).To(MatchAllKeys(Keys{
			"ca.crt":           Not(BeEmpty()),
			"tls.crt":          Not(BeEmpty()),
			"tls.key":          Not(BeEmpty()),
			"tls-combined.pem": Equal(append(append(pkPEM, '\n'), crtPEM...)),
			"key.der":          Equal(block.Bytes),
		}))

		By("renewing Certificate to get new signed certificate and private key")
		oldCrtPEM := secret.Data["tls.crt"]
		oldPKPEM := secret.Data["tls.key"]
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(context.Background(), crtName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "e2e-testing", "Renewing for AdditionalOutputFormat e2e test")
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).UpdateStatus(context.Background(), crt, metav1.UpdateOptions{})
			return err
		})
		Expect(err).NotTo(HaveOccurred())

		crt, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, crt, time.Minute*2)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		By("ensuring additional output formats reflect the new private key and certificate")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		crtPEM = secret.Data["tls.crt"]
		pkPEM = secret.Data["tls.key"]
		block, _ = pem.Decode(pkPEM)
		Expect(secret.Data).To(MatchAllKeys(Keys{
			"ca.crt":           Not(Equal(oldCrtPEM)),
			"tls.crt":          Not(Equal(oldCrtPEM)),
			"tls.key":          Not(Equal(oldPKPEM)),
			"tls-combined.pem": Equal(append(append(pkPEM, '\n'), crtPEM...)),
			"key.der":          Equal(block.Bytes),
		}))
	})

	It("if a third party set additional output formats, they then get added to the Certificate, when they are removed again they should persist as they are still owned by a third party", func() {
		// This e2e test requires that the ServerSideApply feature gate is enabled.
		framework.RequireFeatureGate(utilfeature.DefaultFeatureGate, feature.ServerSideApply)

		crtName, crt := createCertificate(f, nil)

		By("add additional output formats manually to the secret")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		crtPEM := secret.Data["tls.crt"]
		pkPEM := secret.Data["tls.key"]
		block, _ := pem.Decode(pkPEM)
		secret.Data["tls-combined.pem"] = append(append(pkPEM, '\n'), crtPEM...)
		secret.Data["key.der"] = block.Bytes
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(context.Background(), secret, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("add additional output formats to Certificate")
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(context.Background(), crtName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			crt.Spec.AdditionalOutputFormats = []cmapi.CertificateAdditionalOutputFormat{{Type: "CombinedPEM"}, {Type: "DER"}}
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
			return err
		})
		Expect(err).NotTo(HaveOccurred())

		By("wait for cert-manager to assigned ownership to the additional output format fields")
		Eventually(func() bool {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			for _, managedField := range secret.ManagedFields {
				// The field manager of the issuing controller is currently
				// "cert-manager-certificates-issuing".
				if managedField.Manager != "cert-manager-certificates-issuing" || managedField.FieldsV1 == nil {
					continue
				}
				var fieldset fieldpath.Set
				Expect(fieldset.FromJSON(bytes.NewReader(managedField.FieldsV1.Raw))).NotTo(HaveOccurred())
				if fieldset.Has(fieldpath.Path{
					{FieldName: ptr.To("data")},
					{FieldName: ptr.To("tls-combined.pem")},
				}) && fieldset.Has(fieldpath.Path{
					{FieldName: ptr.To("data")},
					{FieldName: ptr.To("key.der")},
				}) {
					return true
				}
			}
			return false
		}).WithTimeout(5 * time.Second).WithPolling(time.Second).Should(BeTrue())

		By("remove additional output formats from Certificate")
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(context.Background(), crtName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			crt.Spec.AdditionalOutputFormats = nil
			crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(context.Background(), crt, metav1.UpdateOptions{})
			return err
		})
		Expect(err).NotTo(HaveOccurred())

		By("observe secret maintain the additional output format keys and values since they are owned by a third party")
		Consistently(func() map[string][]byte {
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.Background(), secretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return secret.Data
		}).WithTimeout(5 * time.Second).WithPolling(time.Second).Should(MatchAllKeys(Keys{
			"ca.crt":           Not(BeEmpty()),
			"tls.crt":          Not(BeEmpty()),
			"tls.key":          Not(BeEmpty()),
			"tls-combined.pem": Equal(append(append(pkPEM, '\n'), crtPEM...)),
			"key.der":          Equal(block.Bytes),
		}))
	})
})
