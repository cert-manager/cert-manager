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
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/e2e/framework"
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
	CreateIssuerFunc func(*framework.Framework) cmapi.ObjectReference

	// DeleteIssuerFunc is a function that is run after the test has completed
	// in order to clean up resources created for a test (e.g. the resources
	// created in CreateIssuerFunc).
	// This function will be run regardless whether the test passes or fails.
	// If not specified, this function will be skipped.
	DeleteIssuerFunc func(*framework.Framework, cmapi.ObjectReference)

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
		s.DomainSuffix = f.Config.Addons.Nginx.Global.Domain
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

		By("Running test suite with the following unsupported features: " + s.UnsupportedFeatures.String())
		ctx := context.Background()
		var issuerRef cmapi.ObjectReference

		JustBeforeEach(func() {
			By("Creating an issuer resource")
			issuerRef = s.CreateIssuerFunc(f)
		})

		JustAfterEach(func() {
			if s.DeleteIssuerFunc == nil {
				By("Skipping cleanup as no DeleteIssuerFunc provided")
				return
			}

			By("Cleaning up the issuer resource")
			s.DeleteIssuerFunc(f, issuerRef)
		})

		It("should issue a basic, defaulted certificate for a single commonName and distinct dnsName", func() {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: s.newDomain(),
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
		})

		It("should issue an ECDSA, defaulted certificate for a single commonName and distinct dnsName", func() {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:   "testcert-tls",
					KeyAlgorithm: cmapi.ECDSAKeyAlgorithm,
					CommonName:   s.newDomain(),
					DNSNames:     []string{s.newDomain()},
					IssuerRef:    issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssuedValid(f.Namespace.Name, "testcert", time.Minute*5)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should issue a certificate that defines a commonName and ipAddresses", func() {
			s.checkFeatures(IPAddressFeature)

			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:  "testcert-tls",
					CommonName:  s.newDomain(),
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
		})
	})
}

// checkFeatures is a helper function that is used to ensure that the features
// required for a given test case are supported by the suite.
func (s *Suite) checkFeatures(fs ...Feature) {
	unsupported := make(FeatureSet)
	for _, f := range fs {
		if s.UnsupportedFeatures.Contains(f) {
			unsupported.Add(f)
		}
	}
	// all features supported, return early!
	if len(unsupported) == 0 {
		return
	}
	Skip("skipping due to the following unsupported features: " + unsupported.String())
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
