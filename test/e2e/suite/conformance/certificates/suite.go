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

package certificates

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	e2eutil "github.com/jetstack/cert-manager/test/e2e/util"
)

// Suite defines a reusable conformance test suite that can be used against any
// Issuer implementation.
type Suite struct {
	// Name is the name of the issuer being tested, e.g. SelfSigned, CA, ACME
	// This field must be provided.
	Name string

	// CreateIssuerFunc is a function that provisions a new issuer resource and
	// returns an ObjectReference to that Issuer that will be used as the
	// IssuerRef on Certificate resources that this suite creates.
	// This field must be provided.
	CreateIssuerFunc func(*framework.Framework) cmmeta.ObjectReference

	// DeleteIssuerFunc is a function that is run after the test has completed
	// in order to clean up resources created for a test (e.g. the resources
	// created in CreateIssuerFunc).
	// This function will be run regardless whether the test passes or fails.
	// If not specified, this function will be skipped.
	DeleteIssuerFunc func(*framework.Framework, cmmeta.ObjectReference)

	// DomainSuffix is a suffix used on all domain requests.
	// This is useful when the issuer being tested requires special
	// configuration for a set of domains in order for certificates to be
	// issued, such as the ACME issuer.
	// If not set, this will be defaulted to the configured 'domain' for the
	// nginx-ingress addon.
	DomainSuffix string

	// UnsupportedFeatures is a list of features that are not supported by this
	// invocation of the test suite.
	// This is useful if a particular issuers explicitly does not support
	// certain features due to restrictions in their implementation.
	UnsupportedFeatures FeatureSet

	// completed is used internally to track whether Complete() has been called
	completed bool
}

// complete will validate configuration and set default values.
func (s *Suite) complete(f *framework.Framework) {
	// TODO: work out how to fail an entire 'Describe' block so we can validate these are correctly set
	//Expect(s.Name).NotTo(Equal(""), "Name must be set")
	//Expect(s.CreateIssuerFunc).NotTo(BeNil(), "CreateIssuerFunc must be set")

	if s.DomainSuffix == "" {
		s.DomainSuffix = f.Config.Addons.IngressController.Domain
	}

	if s.UnsupportedFeatures == nil {
		s.UnsupportedFeatures = make(FeatureSet)
	}

	s.completed = true
}

// Defines simple conformance tests that can be run against any issuer type.
// If Complete has not been called on this Suite before Define, it will be
// automatically called.
func (s *Suite) Define() {
	Describe("with issuer type "+s.Name, func() {
		f := framework.NewDefaultFramework("certificates")

		// wrap this in a BeforeEach else flags will not have been parsed at
		// the time that the `complete` function is called.
		BeforeEach(func() {
			if !s.completed {
				s.complete(f)
			}
		})

		it := func(name string, fn func(cmmeta.ObjectReference), requiredFeatures ...Feature) {
			if !s.checkFeatures(requiredFeatures...) {
				fmt.Fprintln(GinkgoWriter, "skipping case due to unsupported features")
				return
			}
			It(name, func() {
				By("Creating an issuer resource")
				issuerRef := s.CreateIssuerFunc(f)
				defer func() {
					if s.DeleteIssuerFunc != nil {
						By("Cleaning up the issuer resource")
						s.DeleteIssuerFunc(f, issuerRef)
					}
				}()
				fn(issuerRef)
			})
		}

		By("Running test suite with the following unsupported features: " + s.UnsupportedFeatures.String())
		ctx := context.Background()

		it("should issue a basic, defaulted certificate for a single distinct DNS Name", func(issuerRef cmmeta.ObjectReference) {
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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, OnlySAN)

		it("should issue an ECDSA, defaulted certificate for a single distinct dnsName", func(issuerRef cmmeta.ObjectReference) {
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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, ECDSAFeature, OnlySAN)

		it("should issue a basic, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					CommonName: "test-common-name",
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, CommonNameFeature)

		it("should issue an ECDSA, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
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
					CommonName: "test-common-name",
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, ECDSAFeature, CommonNameFeature)

		it("should issue a certificate that defines a Common Name and IP Address", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:  "testcert-tls",
					CommonName:  "test-common-name",
					IPAddresses: []string{"127.0.0.1"},
					IssuerRef:   issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, CommonNameFeature, IPAddressFeature)

		it("should issue a certificate that defines an Email Address", func(issuerRef cmmeta.ObjectReference) {
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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, EmailSANsFeature, OnlySAN)

		it("should issue a certificate that defines a CommonName and URI SAN", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: "test-common-name",
					URIs:       []string{"spiffe://cluster.local/ns/sandbox/sa/foo"},
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, URISANsFeature, CommonNameFeature)

		it("should issue a certificate that defines a 2 distinct DNS Name with one copied to the Common Name", func(issuerRef cmmeta.ObjectReference) {
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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, CommonNameFeature)

		it("should issue a certificate that defines a distinct DNS Name and another distinct Common Name", func(issuerRef cmmeta.ObjectReference) {
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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, CommonNameFeature)

		it("should issue a certificate that defines a DNS Name and sets a duration", func(issuerRef cmmeta.ObjectReference) {
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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			// We set a weird time here as the duration with should never be used as
			// a default by an issuer. This lets us test issuers are using our given
			// duration.
			// We set a 30 second buffer time here since Vault issues certificates
			// with an extra 30 seconds on its duration.
			f.CertificateDurationValid(testCertificate, time.Hour*896, 30*time.Second)
		}, DurationFeature, OnlySAN)

		it("should issue a certificate which has a wildcard DNS name defined", func(issuerRef cmmeta.ObjectReference) {
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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, WildcardsFeature, OnlySAN)

		it("should issue a certificate that includes only a URIs name", func(issuerRef cmmeta.ObjectReference) {
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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, URISANsFeature, OnlySAN)

		it("should issue a certificate that includes arbitrary key usages", func(issuerRef cmmeta.ObjectReference) {
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
					},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		}, KeyUsagesFeature, OnlySAN)

		it("should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted", func(issuerRef cmmeta.ObjectReference) {
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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
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
		}, ReusePrivateKeyFeature, OnlySAN)

		it("should issue a basic, defaulted certificate for a single commonName and distinct dnsName defined by an ingress with annotations", func(issuerRef cmmeta.ObjectReference) {
			ingClient := f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace.Name)

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
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, certName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		})
	})
}

// checkFeatures is a helper function that is used to ensure that the features
// required for a given test case are supported by the suite.
// It will return 'true' if all features are supported and the test should run,
// or return 'false' if any required feature is not supported.
func (s *Suite) checkFeatures(fs ...Feature) bool {
	unsupported := make(FeatureSet)
	for _, f := range fs {
		if s.UnsupportedFeatures.Contains(f) {
			unsupported.Add(f)
		}
	}
	// all features supported, return early!
	if len(unsupported) == 0 {
		return true
	}
	return false
}

// newDomain will generate a new random subdomain of the DomainSuffix
func (s *Suite) newDomain() string {
	return s.newDomainDepth(1)
}

// newDomainDepth return a new domain name with the given number of subdomains
// beneath the domain suffix.
// If depth is zero, the domain suffix will be returned,
// If depth is one, a random subdomain will be returned e.g. abcd.example.com,
// If depth is two, a random sub-subdomain will be returned e.g. abcd.efgh.example.com,
// and so on
func (s *Suite) newDomainDepth(depth int) string {
	subdomains := make([]string, depth)
	for i := 0; i < depth; i++ {
		subdomains[i] = util.RandStringRunes(4)
	}
	return strings.Join(append(subdomains, s.DomainSuffix), ".")
}
