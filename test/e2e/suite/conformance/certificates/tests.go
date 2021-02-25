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
	"context"
	"time"

	"github.com/cert-manager/cert-manager/test/e2e/framework/helper"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/validations"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	e2eutil "github.com/cert-manager/cert-manager/test/e2e/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Defines simple conformance tests that can be run against any issuer type.
// If Complete has not been called on this Suite before Define, it will be
// automatically called.
func (s *Suite) Define() {
	Describe("with issuer type "+s.Name, func() {
		ctx := context.Background()
		f := framework.NewDefaultFramework("certificates")

		// wrap this in a BeforeEach else flags will not have been parsed at
		// the time that the `complete` function is called.
		BeforeEach(func() {
			if !s.completed {
				s.complete(f)
			}
		})
		By("Running test suite with the following unsupported features: " + s.UnsupportedFeatures.String())

		s.it(f, "should issue a basic, defaulted certificate for a single distinct DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{s.newDomain()},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN)

		s.it(f, "should issue an ECDSA, defaulted certificate for a single distinct dnsName", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
					},
					DNSNames:  []string{s.newDomain()},
					IssuerRef: issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.ECDSAFeature, featureset.OnlySAN)

		s.it(f, "should issue a basic, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + util.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					CommonName: cn,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature)

		s.it(f, "should issue an ECDSA, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + util.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
					},
					CommonName: cn,
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.ECDSAFeature, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a Common Name and IP Address", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + util.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:  "testcert-tls",
					CommonName:  cn,
					IPAddresses: []string{"127.0.0.1"},
					IssuerRef:   issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature, featureset.IPAddressFeature)

		s.it(f, "should issue a certificate that defines an Email Address", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:     "testcert-tls",
					EmailAddresses: []string{"alice@example.com"},
					IssuerRef:      issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.EmailSANsFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that defines a CommonName and URI SAN", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + util.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: cn,
					URIs:       []string{"spiffe://cluster.local/ns/sandbox/sa/foo"},
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.URISANsFeature, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a 2 distinct DNS Name with one copied to the Common Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: s.newDomain(),
					IssuerRef:  issuerRef,
				},
			}
			testCertificate.Spec.DNSNames = []string{
				testCertificate.Spec.CommonName, s.newDomain(),
			}

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a distinct DNS Name and another distinct Common Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: s.newDomain(),
					IssuerRef:  issuerRef,
					DNSNames:   []string{s.newDomain()},
				},
			}

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a DNS Name and sets a duration", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{s.newDomain()},
					Duration: &metav1.Duration{
						Duration: time.Hour * 896,
					},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())

			// We set a weird time here as the duration with should never be used as
			// a default by an issuer. This lets us test issuers are using our given
			// duration.
			// We set a 30 second buffer time here since Vault issues certificates
			// with an extra 30 seconds on its duration.
			f.CertificateDurationValid(testCertificate, time.Hour*896, 30*time.Second)
		}, featureset.DurationFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate which has a wildcard DNS name defined", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{"foo." + s.newDomain()},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.WildcardsFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that includes only a URISANs name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					URIs: []string{
						"spiffe://cluster.local/ns/sandbox/sa/foo",
					},
					IssuerRef: issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.URISANsFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that includes arbitrary key usages", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{s.newDomain()},
					IssuerRef:  issuerRef,
					Usages: []cmapi.KeyUsage{
						cmapi.UsageSigning,
						cmapi.UsageDataEncipherment,
						cmapi.UsageServerAuth,
						cmapi.UsageClientAuth,
					},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")

			validations := []helper.ValidationFunc{
				validations.ExpectKeyUsageExtKeyUsageClientAuth,
				validations.ExpectKeyUsageExtKeyUsageServerAuth,
				validations.ExpectKeyUsageUsageDigitalSignature,
				validations.ExpectKeyUsageUsageDataEncipherment,
			}
			validations = append(validations, f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)

			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", validations...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.KeyUsagesFeature, featureset.OnlySAN)

		s.it(f, "should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{s.newDomain()},
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, "testcert", f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())

			By("Deleting existing certificate data in Secret")
			sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).
				Get(context.TODO(), testCertificate.Spec.SecretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get secret containing signed certificate key pair data")

			sec = sec.DeepCopy()
			crtPEM1 := sec.Data[corev1.TLSCertKey]
			crt1, err := pki.DecodeX509CertificateBytes(crtPEM1)
			Expect(err).NotTo(HaveOccurred(), "failed to get decode first signed certificate data")

			sec.Data[corev1.TLSCertKey] = []byte{}

			_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(context.TODO(), sec, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to update secret by deleting the signed certificate data")

			By("Waiting for the Certificate to re-issue a certificate")
			sec, err = f.Helper().WaitForSecretCertificateData(f.Namespace.Name, sec.Name, time.Minute*5)
			Expect(err).NotTo(HaveOccurred(), "failed to wait for secret to have a valid 2nd certificate")

			crtPEM2 := sec.Data[corev1.TLSCertKey]
			crt2, err := pki.DecodeX509CertificateBytes(crtPEM2)
			Expect(err).NotTo(HaveOccurred(), "failed to get decode second signed certificate data")

			By("Ensuing both certificates are signed by same private key")
			match, err := pki.PublicKeysEqual(crt1.PublicKey, crt2.PublicKey)
			Expect(err).NotTo(HaveOccurred(), "failed to check public keys of both signed certificates")

			if !match {
				Fail("Both signed certificates not signed by same private key")
			}
		}, featureset.ReusePrivateKeyFeature, featureset.OnlySAN)

		s.it(f, "should issue a basic certificate for a single distinct dnsName defined by an ingress with annotations", func(issuerRef cmmeta.ObjectReference) {
			ingClient := f.KubeClientSet.NetworkingV1beta1().Ingresses(f.Namespace.Name)

			name := "testcert-ingress"
			secretName := "testcert-ingress-tls"

			By("Creating an Ingress with the issuer name annotation set")
			ingress, err := ingClient.Create(context.TODO(), e2eutil.NewIngress(name, secretName, map[string]string{
				"cert-manager.io/issuer":       issuerRef.Name,
				"cert-manager.io/issuer-kind":  issuerRef.Kind,
				"cert-manager.io/issuer-group": issuerRef.Group,
			}, s.newDomain()), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			certName := ingress.Spec.TLS[0].SecretName

			By("Waiting for the Certificate to exist...")
			Expect(e2eutil.WaitForCertificateToExist(
				f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name), certName, time.Minute,
			)).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, certName, f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN)

		s.it(f, "should issue a basic certificate defined by an ingress with certificate field annotations", func(issuerRef cmmeta.ObjectReference) {
			ingClient := f.KubeClientSet.NetworkingV1beta1().Ingresses(f.Namespace.Name)

			name := "testcert-ingress"
			secretName := "testcert-ingress-tls"
			domain := s.newDomain()
			duration := time.Hour * 999
			renewBefore := time.Hour * 111

			By("Creating an Ingress with annotations for issuerRef and other Certificate fields")
			ingress, err := ingClient.Create(context.TODO(), e2eutil.NewIngress(name, secretName, map[string]string{
				"cert-manager.io/issuer":       issuerRef.Name,
				"cert-manager.io/issuer-kind":  issuerRef.Kind,
				"cert-manager.io/issuer-group": issuerRef.Group,
				"cert-manager.io/common-name":  domain,
				"cert-manager.io/duration":     duration.String(),
				"cert-manager.io/renew-before": renewBefore.String(),
			}, domain), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			certName := ingress.Spec.TLS[0].SecretName

			By("Waiting for the Certificate to exist...")
			Expect(e2eutil.WaitForCertificateToExist(
				f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name), certName, time.Minute,
			)).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			// Verify that the ingres-shim has translated all the supplied
			// annotations into equivalent Certificate field values
			By("Validating the created Certificate")
			err = f.Helper().ValidateCertificate(
				f.Namespace.Name, certName,
				func(certificate *cmapi.Certificate, _ *corev1.Secret) error {
					Expect(certificate.Spec.DNSNames).To(ConsistOf(domain))
					Expect(certificate.Spec.CommonName).To(Equal(domain))
					Expect(certificate.Spec.Duration.Duration).To(Equal(duration))
					Expect(certificate.Spec.RenewBefore.Duration).To(Equal(renewBefore))
					return nil
				},
			)

			// Verify that the issuer has preserved all the Certificate values
			// in the signed certificate
			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, certName, f.Helper().ValidationSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		})
	})
}
