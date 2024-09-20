/*
Copyright 2021 The cert-manager Authors.

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

package certificatesigningrequests

import (
	"context"
	"crypto/x509"
	"net"
	"net/url"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificatesigningrequests"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Defines simple conformance tests that can be run against any issuer type.
// If Complete has not been called on this Suite before Define, it will be
// automatically called.
// The tests in this file require that the CertificateSigningRequest
// controllers are active
// (--feature-gates=ExperimentalCertificateSigningRequestControllers=true). If
// they are not active, these tests will fail.
func (s *Suite) Define() {
	Describe("CertificateSigningRequest with issuer type "+s.Name, func() {
		f := framework.NewDefaultFramework("certificatesigningrequests")
		s.setup(f)

		sharedURI, err := url.Parse("spiffe://cluster.local/ns/sandbox/sa/foo")
		if err != nil {
			// This should never happen, and is a bug. Panic to prevent garbage test
			// data.
			panic(err)
		}

		// Wrap this in a BeforeEach else flags will not have been parsed and
		// f.Config will not be populated at the time that this code is run.
		BeforeEach(func() {
			s.validate()
		})

		type testCase struct {
			name    string // ginkgo v2 does not support using map[string] to store the test names (#5345)
			keyAlgo x509.PublicKeyAlgorithm
			// csrModifiers define the shape of the X.509 CSR which is used in the
			// test case. We use a function to allow access to variables that are
			// initialized at test runtime by complete().
			csrModifiers             []gen.CSRModifier
			kubeCSRUsages            []certificatesv1.KeyUsage
			kubeCSRAnnotations       map[string]string
			kubeCSRExpirationSeconds *int32
			// The list of features that are required by the Issuer for the test to
			// run.
			requiredFeatures []featureset.Feature
			// Extra validations which may be needed for testing, on a test case by
			// case basis. All default validations will be run on every test.
			extraValidations []certificatesigningrequests.ValidationFunc
		}

		tests := []testCase{
			{
				name:    "should issue an RSA certificate for a single distinct DNS Name",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN},
			},
			{
				name:    "should issue an ECDSA certificate for a single distinct DNS Name",
				keyAlgo: x509.ECDSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.ECDSAFeature, featureset.OnlySAN},
			},
			{
				name:    "should issue an Ed25519 certificate for a single distinct DNS Name",
				keyAlgo: x509.Ed25519,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.Ed25519FeatureSet, featureset.OnlySAN},
			},
			{
				name:    "should issue an RSA certificate for a single Common Name",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRCommonName("test-common-name-" + rand.String(10)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature},
			},
			{
				name:    "should issue an ECDSA certificate for a single Common Name",
				keyAlgo: x509.ECDSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRCommonName("test-common-name-" + rand.String(10)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.ECDSAFeature},
			},
			{
				name:    "should issue an Ed25519 certificate for a single Common Name",
				keyAlgo: x509.Ed25519,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRCommonName("test-common-name-" + rand.String(10)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.Ed25519FeatureSet},
			},
			{
				name:    "should issue a certificate that defines a Common Name and IP Address",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRCommonName("test-common-name-" + rand.String(10)),
					gen.SetCSRIPAddresses(net.ParseIP(s.SharedIPAddress)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.IPAddressFeature},
			},
			{
				name:    "should issue a certificate that defines an IP Address",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRIPAddresses(net.ParseIP(s.SharedIPAddress)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.IPAddressFeature},
			},
			{
				name:    "should issue a certificate that defines a DNS Name and IP Address",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRIPAddresses(net.ParseIP(s.SharedIPAddress)),
					gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.IPAddressFeature},
			},
			{
				name:    "should issue a CA certificate with the CA basicConstraint set",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				kubeCSRAnnotations: map[string]string{
					experimentalapi.CertificateSigningRequestIsCAAnnotationKey: "true",
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.IssueCAFeature},
			},
			{
				name:    "should issue a certificate that defines an Email Address",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSREmails([]string{"alice@example.com", "bob@cert-manager.io"}),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.EmailSANsFeature},
			},
			{
				name:    "should issue a certificate that defines a Common Name and URI SAN",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRCommonName("test-common-name-" + rand.String(10)),
					gen.SetCSRURIs(sharedURI),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.URISANsFeature},
			},
			{
				name:    "should issue a certificate that define 2 distinct DNS Names with one copied to the Common Name",
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					commonName := e2eutil.RandomSubdomain(s.DomainSuffix)

					return []gen.CSRModifier{
						gen.SetCSRCommonName(commonName),
						gen.SetCSRDNSNames(commonName, e2eutil.RandomSubdomain(s.DomainSuffix)),
					}
				}(),
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature},
			},
			{
				name:    "should issue a certificate that defines a distinct DNS Name and another distinct Common Name",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRCommonName(e2eutil.RandomSubdomain(s.DomainSuffix)),
					gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature},
			},
			{
				name:    "should issue a certificate that defines a Common Name, DNS Name, and sets a duration",
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					commonName := e2eutil.RandomSubdomain(s.DomainSuffix)

					return []gen.CSRModifier{
						gen.SetCSRCommonName(commonName),
						gen.SetCSRDNSNames(commonName),
					}
				}(),
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				kubeCSRAnnotations: map[string]string{
					experimentalapi.CertificateSigningRequestDurationAnnotationKey: "896h",
				},
				requiredFeatures: []featureset.Feature{featureset.DurationFeature},
			},
			{
				name:    "should issue a certificate that defines a Common Name, DNS Name, and sets a duration via expiration seconds",
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					commonName := e2eutil.RandomSubdomain(s.DomainSuffix)

					return []gen.CSRModifier{
						gen.SetCSRCommonName(commonName),
						gen.SetCSRDNSNames(commonName),
					}
				}(),
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				kubeCSRExpirationSeconds: ptr.To(int32(3333)),
				requiredFeatures:         []featureset.Feature{featureset.DurationFeature},
			},
			{
				name:    "should issue a certificate that defines a DNS Name and sets a duration",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				kubeCSRAnnotations: map[string]string{
					experimentalapi.CertificateSigningRequestDurationAnnotationKey: "896h",
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.DurationFeature},
			},
			{
				name:    "should issue a certificate which has a wildcard DNS Name defined",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRDNSNames("*." + e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.WildcardsFeature, featureset.OnlySAN},
			},
			{
				name:    "should issue a certificate which has a wildcard DNS Name and its apex DNS Name defined",
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					dnsDomain := e2eutil.RandomSubdomain(s.DomainSuffix)

					return []gen.CSRModifier{
						gen.SetCSRDNSNames("*."+dnsDomain, dnsDomain),
					}
				}(),
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.WildcardsFeature, featureset.OnlySAN},
			},
			{
				name:    "should issue a certificate that includes only a URISANs name",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRURIs(sharedURI),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.URISANsFeature, featureset.OnlySAN},
			},
			{
				name:    "should issue a certificate that includes arbitrary key usages with common name",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRCommonName(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageServerAuth,
					certificatesv1.UsageClientAuth,
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageDataEncipherment,
				},
				extraValidations: []certificatesigningrequests.ValidationFunc{
					certificatesigningrequests.ExpectKeyUsageExtKeyUsageClientAuth,
					certificatesigningrequests.ExpectKeyUsageExtKeyUsageServerAuth,
					certificatesigningrequests.ExpectKeyUsageUsageDigitalSignature,
					certificatesigningrequests.ExpectKeyUsageUsageDataEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.KeyUsagesFeature},
			},
			{
				name:    "should issue a signing CA certificate that has a large duration",
				keyAlgo: x509.RSA,
				csrModifiers: []gen.CSRModifier{
					gen.SetCSRCommonName("cert-manager-ca"),
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
					certificatesv1.UsageCertSign,
				},
				kubeCSRAnnotations: map[string]string{
					experimentalapi.CertificateSigningRequestDurationAnnotationKey: "10000h",
					experimentalapi.CertificateSigningRequestIsCAAnnotationKey:     "true",
				},
				requiredFeatures: []featureset.Feature{featureset.KeyUsagesFeature, featureset.DurationFeature, featureset.CommonNameFeature},
			},
			{
				name:    "should issue a certificate that defines a long domain",
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					const maxLengthOfDomainSegment = 63
					return []gen.CSRModifier{
						gen.SetCSRDNSNames(e2eutil.RandomSubdomainLength(s.DomainSuffix, maxLengthOfDomainSegment)),
					}
				}(),
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.LongDomainFeatureSet},
			},
		}

		addAnnotation := func(annotations map[string]string, key, value string) map[string]string {
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations[key] = value
			return annotations
		}

		defineTest := func(test testCase) {
			s.it(f, test.name, func(ctx context.Context, signerName string) {
				// Generate request CSR
				csr, key, err := gen.CSR(test.keyAlgo, test.csrModifiers...)
				Expect(err).NotTo(HaveOccurred())

				// Create CertificateSigningRequest
				randomTestID := rand.String(10)
				kubeCSR := &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "e2e-conformance-" + randomTestID,
						Annotations: addAnnotation(
							test.kubeCSRAnnotations,
							"conformance.cert-manager.io/test-name",
							s.Name+" "+test.name,
						),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Request:           csr,
						SignerName:        signerName,
						Usages:            test.kubeCSRUsages,
						ExpirationSeconds: test.kubeCSRExpirationSeconds,
					},
				}

				// Provision any resources needed for the request, or modify the
				// request based on Issuer requirements
				if s.ProvisionFunc != nil {
					s.ProvisionFunc(ctx, f, kubeCSR, key)
				}
				// Ensure related resources are cleaned up at the end of the test
				if s.DeProvisionFunc != nil {
					defer s.DeProvisionFunc(ctx, f, kubeCSR)
				}

				// Create the request, and delete at the end of the test
				By("Creating a CertificateSigningRequest")
				Expect(f.CRClient.Create(ctx, kubeCSR)).NotTo(HaveOccurred())
				// nolint: contextcheck // This is a cleanup context
				defer func() {
					cleanupCtx := context.Background()

					err := f.CRClient.Delete(cleanupCtx, kubeCSR)
					Expect(err).NotTo(HaveOccurred())
				}()

				// Approve the request for testing, so that cert-manager may sign the
				// request.
				By("Approving CertificateSigningRequest")
				kubeCSR.Status.Conditions = append(kubeCSR.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "e2e.cert-manager.io",
					Message: "Request approved for e2e testing.",
				})
				kubeCSR, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, kubeCSR.Name, kubeCSR, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Wait for the status.Certificate and CA annotation to be populated in
				// a reasonable amount of time.
				By("Waiting for the CertificateSigningRequest to be issued...")
				kubeCSR, err = f.Helper().WaitForCertificateSigningRequestSigned(ctx, kubeCSR.Name, time.Minute*5)
				Expect(err).NotTo(HaveOccurred())

				// Validate that the request was signed as expected. Add extra
				// validations which may be required for this test.
				By("Validating the issued CertificateSigningRequest...")
				validations := []certificatesigningrequests.ValidationFunc(nil)
				validations = append(validations, test.extraValidations...)
				validations = append(validations, validation.CertificateSigningRequestSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
				err = f.Helper().ValidateCertificateSigningRequest(kubeCSR.Name, key, validations...)
				Expect(err).NotTo(HaveOccurred())
			}, test.requiredFeatures...)
		}

		for _, tc := range tests {
			defineTest(tc)
		}
	})
}
