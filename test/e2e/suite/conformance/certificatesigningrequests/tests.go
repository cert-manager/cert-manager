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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/validation"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/validation/certificatesigningrequests"
	e2eutil "github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
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
		ctx := context.Background()
		f := framework.NewDefaultFramework("certificatesigningrequests")

		sharedCommonName := "<SHOULD_GET_REPLACED>"
		sharedURI, err := url.Parse("spiffe://cluster.local/ns/sandbox/sa/foo")
		if err != nil {
			// This should never happen, and is a bug. Panic to prevent garbage test
			// data.
			panic(err)
		}

		// Wrap this in a BeforeEach else flags will not have been parsed and
		// f.Config will not be populated at the time that this code is run.
		BeforeEach(func() {
			if s.completed {
				return
			}

			s.complete(f)

			sharedCommonName = e2eutil.RandomSubdomain(s.DomainSuffix)
		})

		type testCase struct {
			keyAlgo x509.PublicKeyAlgorithm
			// csrModifers define the shape of the X.509 CSR which is used in the
			// test case. We use a function to allow access to variables that are
			// initialized at test runtime by complete().
			csrModifiers             func() []gen.CSRModifier
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

		tests := map[string]testCase{
			"should issue an RSA certificate for a single distinct DNS Name": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix))}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN},
			},

			"should issue an ECDSA certificate for a single distinct DNS Name": {
				keyAlgo: x509.ECDSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix))}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.ECDSAFeature, featureset.OnlySAN},
			},

			"should issue an Ed25519 certificate for a single distinct DNS Name": {
				keyAlgo: x509.Ed25519,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix))}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.Ed25519FeatureSet, featureset.OnlySAN},
			},

			"should issue an RSA certificate for a single Common Name": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{gen.SetCSRCommonName("test-common-name-" + util.RandStringRunes(10))}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature},
			},

			"should issue an ECDSA certificate for a single Common Name": {
				keyAlgo: x509.ECDSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{gen.SetCSRCommonName("test-common-name-" + util.RandStringRunes(10))}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.ECDSAFeature},
			},

			"should issue an Ed25519 certificate for a single Common Name": {
				keyAlgo: x509.Ed25519,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{gen.SetCSRCommonName("test-common-name-" + util.RandStringRunes(10))}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.Ed25519FeatureSet},
			},

			"should issue a certificate that defines a Common Name and IP Address": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRCommonName("test-common-name-" + util.RandStringRunes(10)),
						gen.SetCSRIPAddresses(net.IPv4(127, 0, 0, 1), net.IPv4(8, 8, 8, 8)),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.IPAddressFeature},
			},

			"should issue a certificate that defines an Email Address": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSREmails([]string{"alice@example.com", "bob@cert-manager.io"}),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.EmailSANsFeature},
			},

			"should issue a certificate that defines a Common Name and URI SAN": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRCommonName("test-common-name-" + util.RandStringRunes(10)),
						gen.SetCSRURIs(sharedURI),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.URISANsFeature},
			},

			"should issue a certificate that defines a 2 distinct DNS Name with one copied to the Common Name": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRCommonName(sharedCommonName),
						gen.SetCSRDNSNames(sharedCommonName, e2eutil.RandomSubdomain(s.DomainSuffix)),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{},
			},

			"should issue a certificate that defines a distinct DNS Name and another distinct Common Name": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRCommonName(e2eutil.RandomSubdomain(s.DomainSuffix)),
						gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature},
			},

			"should issue a certificate that defines a Common Name, DNS Name, and sets a duration": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRDNSNames(sharedCommonName),
						gen.SetCSRDNSNames(sharedCommonName),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				kubeCSRAnnotations: map[string]string{
					experimentalapi.CertificateSigningRequestDurationAnnotationKey: "896h",
				},
				requiredFeatures: []featureset.Feature{featureset.DurationFeature},
			},

			"should issue a certificate that defines a Common Name, DNS Name, and sets a duration via expiration seconds": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRDNSNames(sharedCommonName),
						gen.SetCSRDNSNames(sharedCommonName),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				kubeCSRExpirationSeconds: pointer.Int32(3333),
				requiredFeatures:         []featureset.Feature{featureset.DurationFeature},
			},

			"should issue a certificate that defines a DNS Name and sets a duration": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
					}
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

			"should issue a certificate which has a wildcard DNS Name defined": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRDNSNames("*." + e2eutil.RandomSubdomain(s.DomainSuffix)),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.WildcardsFeature, featureset.OnlySAN},
			},

			"should issue a certificate that includes only a URISANs name": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRURIs(sharedURI),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageKeyEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.URISANsFeature, featureset.OnlySAN},
			},

			"should issue a certificate that includes arbitrary key usages": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRCommonName(sharedCommonName),
						gen.SetCSRDNSNames(sharedCommonName),
					}
				},
				kubeCSRUsages: []certificatesv1.KeyUsage{
					certificatesv1.UsageServerAuth,
					certificatesv1.UsageClientAuth,
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageDataEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.KeyUsagesFeature},
				extraValidations: []certificatesigningrequests.ValidationFunc{
					certificatesigningrequests.ExpectKeyUsageExtKeyUsageClientAuth,
					certificatesigningrequests.ExpectKeyUsageExtKeyUsageServerAuth,
					certificatesigningrequests.ExpectKeyUsageUsageDigitalSignature,
					certificatesigningrequests.ExpectKeyUsageUsageDataEncipherment,
				},
			},

			"should issue a signing CA certificate that has a large duration": {
				keyAlgo: x509.RSA,
				csrModifiers: func() []gen.CSRModifier {
					return []gen.CSRModifier{
						gen.SetCSRCommonName("cert-manager-ca"),
					}
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
		}

		defineTest := func(name string, test testCase) {
			s.it(f, name, func(signerName string) {
				// Generate request CSR
				csr, key, err := gen.CSR(test.keyAlgo, test.csrModifiers()...)
				Expect(err).NotTo(HaveOccurred())

				// Create CertificateSigningRequest
				kubeCSR := &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: "e2e-conformance-",
						Annotations:  test.kubeCSRAnnotations,
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
					s.ProvisionFunc(f, kubeCSR, key)
				}
				// Ensure related resources are cleaned up at the end of the test
				if s.DeProvisionFunc != nil {
					defer s.DeProvisionFunc(f, kubeCSR)
				}

				// Create the request, and delete at the end of the test
				By("Creating a CertificateSigningRequest")
				Expect(f.CRClient.Create(ctx, kubeCSR)).NotTo(HaveOccurred())
				defer f.CRClient.Delete(context.TODO(), kubeCSR)

				// Approve the request for testing, so that cert-manager may sign the
				// request.
				By("Approving CertificateSigningRequest")
				kubeCSR.Status.Conditions = append(kubeCSR.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "e2e.cert-manager.io",
					Message: "Request approved for e2e testing.",
				})
				kubeCSR, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), kubeCSR.Name, kubeCSR, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Wait for the status.Certificate and CA annotation to be populated in
				// a reasonable amount of time.
				By("Waiting for the CertificateSigningRequest to be issued...")
				kubeCSR, err = f.Helper().WaitForCertificateSigningRequestSigned(kubeCSR.Name, time.Minute*5)
				Expect(err).NotTo(HaveOccurred())

				// Validate that the request was signed as expected. Add extra
				// validations which may be required for this test.
				By("Validating the issued CertificateSigningRequest...")
				validations := append(test.extraValidations, validation.CertificateSigningRequestSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
				err = f.Helper().ValidateCertificateSigningRequest(kubeCSR.Name, key, validations...)
				Expect(err).NotTo(HaveOccurred())
			}, test.requiredFeatures...)
		}

		for name := range tests {
			defineTest(name, tests[name])
		}
	})
}
