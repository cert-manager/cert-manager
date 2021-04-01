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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmutil "github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
	. "github.com/jetstack/cert-manager/test/e2e/framework/matcher"
	frameworkutil "github.com/jetstack/cert-manager/test/e2e/framework/util"
	"github.com/jetstack/cert-manager/test/e2e/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

const testingACMEEmail = "e2e@cert-manager.io"
const testingACMEPrivateKey = "test-acme-private-key"
const foreverTestTimeout = time.Second * 60

var _ = framework.CertManagerDescribe("ACME Certificate (HTTP01)", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-http01")
	h := f.Helper()

	var acmeIngressDomain string
	issuerName := "test-acme-issuer"
	certificateName := "test-acme-certificate"
	certificateSecretName := "test-acme-certificate"
	// fixedIngressName is the name of an ingress resource that is configured
	// with a challenge solve.
	// To utilise this solver, add the 'testing.cert-manager.io/fixed-ingress: "true"' label.
	fixedIngressName := "testingress"

	// ACME Issuer does not return a ca.crt. See:
	// https://github.com/jetstack/cert-manager/issues/1571
	unsupportedFeatures := featureset.NewFeatureSet(featureset.SaveCAToSecret)
	sanityChecksWithoutx509Validation := f.Helper().ValidationSetForUnsupportedFeatureSet(unsupportedFeatures)

	BeforeEach(func() {
		solvers := []cmacme.ACMEChallengeSolver{
			{
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
						Class: &f.Config.Addons.IngressController.IngressClass,
					},
				},
			},
			{
				Selector: &cmacme.CertificateDNSNameSelector{
					MatchLabels: map[string]string{
						"testing.cert-manager.io/fixed-ingress": "true",
					},
				},
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
						Name: fixedIngressName,
					},
				},
			},
		}
		acmeIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerACMEEmail(testingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMEPrivKeyRef(testingACMEPrivateKey),
			gen.SetIssuerACMESkipTLSVerify(true),
			gen.SetIssuerACMESolvers(solvers))
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			func(i *v1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), testingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}
	})

	JustBeforeEach(func() {
		acmeIngressDomain = frameworkutil.RandomSubdomain(f.Config.Addons.IngressController.Domain)
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuerName, metav1.DeleteOptions{})
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), testingACMEPrivateKey, metav1.DeleteOptions{})
	})

	It("should obtain a signed certificate with a single CN from the ACME server", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(acmeIngressDomain),
		)
		cert.Namespace = f.Namespace.Name

		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed ecdsa certificate with a single CN from the ACME server", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{
				Name: issuerName,
			}),
			gen.SetCertificateDNSNames(acmeIngressDomain),
			gen.SetCertificateKeyAlgorithm(v1.ECDSAKeyAlgorithm),
		)
		cert.Namespace = f.Namespace.Name
		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate for a long domain using http01 validation", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		// the maximum length of a single segment of the domain being requested
		const maxLengthOfDomainSegment = 63
		By("Creating a Certificate")

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(acmeIngressDomain, fmt.Sprintf("%s.%s", cmutil.RandStringRunes(maxLengthOfDomainSegment), acmeIngressDomain)),
		)
		cert.Namespace = f.Namespace.Name

		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certific")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with a CN and single subdomain as dns name from the ACME server", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)),
		)
		cert.Namespace = f.Namespace.Name

		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the Certificate is valid")

		By("Waiting for the Certificate to be issued")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-checking the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow updating an existing certificate with a new dns name", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)),
		)
		cert.Namespace = f.Namespace.Name

		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the Certificate is valid")

		By("Waiting for the Certificate to be issued")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-checking the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())

		By("Getting the latest version of the Certificate")
		cert, err = certClient.Get(context.TODO(), certificateName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Adding an additional dnsName to the Certificate")
		newDNSName := fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)
		cert.Spec.DNSNames = append(cert.Spec.DNSNames, newDNSName)

		By("Updating the Certificate in the apiserver")
		_, err = certClient.Update(context.TODO(), cert, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be not ready")
		_, err = h.WaitForCertificateNotReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-checking the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow updating the dns name of a failing certificate that had an incorrect dns name", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a failing Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames("google.com"),
		)
		cert.Namespace = f.Namespace.Name

		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Making sure the Order failed with a 400 since google.com is invalid")
		order := &cmacme.Order{}
		err = wait.PollImmediate(1*time.Second, 1*time.Minute, func() (done bool, err error) {
			orders, err := listOwnedOrders(f.CertManagerClientSet, cert)
			Expect(err).NotTo(HaveOccurred())

			if len(orders) == 0 || len(orders) > 1 {
				log.Logf("Waiting as one Order should exist, but we found %d", len(orders))
				return false, nil
			}
			order = orders[0]

			expected := `400 urn:ietf:params:acme:error:rejectedIdentifier`
			if !strings.Contains(order.Status.Reason, expected) {
				log.Logf("Waiting for Order's reason, current: %s, should contain: %s", order.Status.Reason, expected)
				return false, nil
			}

			return true, nil
		})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be not ready")
		_, err = h.WaitForCertificateNotReady(f.Namespace.Name, certificateName, 30*time.Second)
		Expect(err).NotTo(HaveOccurred())

		By("Getting the latest version of the Certificate")
		cert, err = certClient.Get(context.TODO(), certificateName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Replacing dnsNames with a valid dns name")
		cert.Spec.DNSNames = []string{fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)}
		_, err = certClient.Update(context.TODO(), cert, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to have the Ready=True condition")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity checking the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())

		By("Checking that the secret contains this dns name")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, func(cert *v1.Certificate, secret *corev1.Secret) error {
			dnsnames, err := findDNSNames(secret)
			if err != nil {
				return err
			}
			Expect(cert.Spec.DNSNames).To(ContainElements(dnsnames))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to obtain a certificate for an invalid ACME dns name", func() {
		// create test fixture
		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames("google.com"),
		)
		cert.Namespace = f.Namespace.Name

		cert, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		notReadyCondition := v1.CertificateCondition{
			Type:   v1.CertificateConditionReady,
			Status: cmmeta.ConditionFalse,
		}
		Eventually(cert, "30s", "1s").Should(HaveCondition(f, notReadyCondition))
		Consistently(cert, "1m", "10s").Should(HaveCondition(f, notReadyCondition))
	})

	It("should obtain a signed certificate with a single CN from the ACME server when putting an annotation on an ingress resource", func() {
		ingClient := f.KubeClientSet.NetworkingV1beta1().Ingresses(f.Namespace.Name)
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating an Ingress with the issuer name annotation set")
		_, err := ingClient.Create(context.TODO(), util.NewIngress(certificateSecretName, certificateSecretName, map[string]string{
			"cert-manager.io/issuer": issuerName,
		}, acmeIngressDomain), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Certificate to exist")
		err = util.WaitForCertificateToExist(certClient, certificateSecretName, foreverTestTimeout)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with a single CN from the ACME server when redirected", func() {

		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		// force-ssl-redirect should make every request turn into a redirect,
		// but I haven't been able to make this happen. Create a TLS cert via
		// the self-sign issuer to make it have a "proper" TLS cert
		// TODO: investigate if we still need to use the self-signed issuer here

		issuer := gen.Issuer("selfsign",
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(v1.SelfSignedIssuer{}))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for (selfsign) Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		const dummycert = "dummy-tls"
		const secretname = "dummy-tls-secret"

		selfcert := util.NewCertManagerBasicCertificate("dummy-tls", secretname, "selfsign", v1.IssuerKind, nil, nil, acmeIngressDomain)
		_, err = certClient.Create(context.TODO(), selfcert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, dummycert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, dummycert, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())

		// create an ingress that points at nothing, but has the TLS redirect annotation set
		// using the TLS secret that we just got from the self-sign
		ingress := f.KubeClientSet.NetworkingV1beta1().Ingresses(f.Namespace.Name)
		_, err = ingress.Create(context.TODO(), &networkingv1beta1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name: fixedIngressName,
				Annotations: map[string]string{
					"nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
					"kubernetes.io/ingress.class":                    "nginx",
				},
			},
			Spec: networkingv1beta1.IngressSpec{
				TLS: []networkingv1beta1.IngressTLS{
					{
						Hosts:      []string{acmeIngressDomain},
						SecretName: secretname,
					},
				},
				Rules: []networkingv1beta1.IngressRule{
					{
						Host: acmeIngressDomain,
						IngressRuleValue: networkingv1beta1.IngressRuleValue{
							HTTP: &networkingv1beta1.HTTPIngressRuleValue{
								Paths: []networkingv1beta1.HTTPIngressPath{
									{
										Path: "/",
										Backend: networkingv1beta1.IngressBackend{
											ServiceName: "doesnotexist",
											ServicePort: intstr.FromInt(443),
										},
									},
								},
							},
						},
					},
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating a Certificate")
		// This is a special cert for the test suite, where we specify an ingress rather than a
		// class
		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(acmeIngressDomain),
		)
		cert.Namespace = f.Namespace.Name
		cert.Labels = map[string]string{
			"testing.cert-manager.io/fixed-ingress": "true",
		}

		_, err = certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should automatically recreate challenge pod and still obtain a certificate if it is manually deleted", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(acmeIngressDomain),
		)
		cert.Namespace = f.Namespace.Name
		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("killing the solver pod")
		podClient := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name)
		var pod corev1.Pod
		err = wait.PollImmediate(1*time.Second, time.Minute,
			func() (bool, error) {
				log.Logf("Waiting for solver pod to exist")
				podlist, err := podClient.List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					return false, err
				}

				for _, p := range podlist.Items {
					log.Logf("solver pod %s", p.Name)
					// TODO(dmo): make this cleaner instead of just going by name
					if strings.Contains(p.Name, "http-solver") {
						pod = p
						return true, nil
					}
				}
				return false, nil

			},
		)
		Expect(err).NotTo(HaveOccurred())

		err = podClient.Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// The pod should get remade and the certificate should be made valid.
		// Killing the pod could potentially make the validation invalid if pebble
		// were to ask us for the challenge after the pod was killed, but because
		// we kill it so early, we should always be in the self-check phase
		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with a single IP Address from the ACME server", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateIPs(f.Config.Addons.ACMEServer.IngressIP),
		)
		cert.Namespace = f.Namespace.Name

		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with an IP and DNS names from the ACME server", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(fmt.Sprintf("%s.%s", cmutil.RandStringRunes(2), acmeIngressDomain)),
			gen.SetCertificateIPs(f.Config.Addons.ACMEServer.IngressIP),
		)
		cert.Namespace = f.Namespace.Name

		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow updating an existing certificate with a new dns name", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)),
		)
		cert.Namespace = f.Namespace.Name

		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())

		By("Getting the latest version of the Certificate")
		cert, err = certClient.Get(context.TODO(), certificateName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Adding an additional dnsName to the Certificate")
		newDNSName := fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)
		cert.Spec.DNSNames = append(cert.Spec.DNSNames, newDNSName)

		By("Updating the Certificate in the apiserver")
		cert, err = certClient.Update(context.TODO(), cert, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be not ready")
		_, err = h.WaitForCertificateNotReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be ready")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity-check the issued Certificate")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, sanityChecksWithoutx509Validation...)
		Expect(err).NotTo(HaveOccurred())
	})

})

// findDNSNames decodes and returns the dns names (SANs) contained in a
// certificate secret.
func findDNSNames(s *corev1.Secret) ([]string, error) {
	if s.Data == nil {
		return nil, fmt.Errorf("secret contains no data")
	}
	pkData := s.Data[corev1.TLSPrivateKeyKey]
	certData := s.Data[corev1.TLSCertKey]
	if len(pkData) == 0 || len(certData) == 0 {
		return nil, fmt.Errorf("missing data in CA secret")
	}
	cert, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data in CA secret: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("internal error parsing x509 certificate: %w", err)
	}

	return x509Cert.DNSNames, nil
}
