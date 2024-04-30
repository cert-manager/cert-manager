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

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
	"github.com/cert-manager/cert-manager/e2e-tests/util"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/cert-manager/cert-manager/e2e-tests/framework/matcher"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CertManagerDescribe("ACME Certificate (HTTP01)", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-http01")
	ctx := context.TODO()

	var acmeIngressDomain string
	issuerName := "test-acme-issuer"
	certificateName := "test-acme-certificate"
	certificateSecretName := "test-acme-certificate"
	// fixedIngressName is the name of an ingress resource that is configured
	// with a challenge solve.
	// To utilise this solver, add the 'testing.cert-manager.io/fixed-ingress: "true"' label.
	fixedIngressName := "testingress"

	// ACME Issuer does not return a ca.crt. See:
	// https://github.com/cert-manager/cert-manager/issues/1571
	unsupportedFeatures := featureset.NewFeatureSet(featureset.SaveCAToSecret)
	validations := validation.CertificateSetForUnsupportedFeatureSet(unsupportedFeatures)

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
			gen.SetIssuerACMEEmail(f.Config.Addons.ACMEServer.TestingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMEPrivKeyRef(f.Config.Addons.ACMEServer.TestingACMEPrivateKey),
			gen.SetIssuerACMESkipTLSVerify(true),
			gen.SetIssuerACMESolvers(solvers))
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			func(i *v1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(ctx, f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}
	})

	JustBeforeEach(func() {
		acmeIngressDomain = e2eutil.RandomSubdomain(f.Config.Addons.IngressController.Domain)
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, issuerName, metav1.DeleteOptions{})
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(ctx, f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.DeleteOptions{})
	})

	It("should allow updating an existing failing certificate that had a blocked dns name", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a failing Certificate")
		// In "make/config/pebble/chart/templates/configmap.yaml"
		// the "google.com" domain is configured in the pebble blocklist.
		cert := gen.Certificate(certificateName,
			gen.SetCertificateNamespace(f.Namespace.Name),
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames("google.com"),
		)
		cert, err := certClient.Create(ctx, cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Making sure the Order failed with a 400 since google.com is invalid")
		order := &cmacme.Order{}
		logf, done := log.LogBackoff()
		defer done()
		err = wait.PollUntilContextTimeout(ctx, 1*time.Second, 1*time.Minute, true, func(ctx context.Context) (done bool, err error) {
			orders, err := listOwnedOrders(ctx, f.CertManagerClientSet, cert)
			Expect(err).NotTo(HaveOccurred())

			if len(orders) == 0 || len(orders) > 1 {
				logf("Waiting as one Order should exist, but we found %d", len(orders))
				return false, nil
			}
			order = orders[0]

			expected := `400 urn:ietf:params:acme:error:rejectedIdentifier`
			if !strings.Contains(order.Status.Reason, expected) {
				logf("Waiting for Order's reason, current: %s, should contain: %s", order.Status.Reason, expected)
				return false, nil
			}

			return true, nil
		})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be not ready")
		cert, err = f.Helper().WaitForCertificateNotReadyAndDoneIssuing(ctx, cert, 30*time.Second)
		Expect(err).NotTo(HaveOccurred())

		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			By("Getting the latest version of the Certificate")
			cert, err = certClient.Get(ctx, certificateName, metav1.GetOptions{})
			if err != nil {
				return err
			}

			By("Replacing dnsNames with a valid dns name")
			cert = cert.DeepCopy()
			cert.Spec.DNSNames = []string{e2eutil.RandomSubdomain(acmeIngressDomain)}
			_, err = certClient.Update(ctx, cert, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to have the Ready=True condition")
		cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Sanity checking the issued Certificate")
		err = f.Helper().ValidateCertificate(cert, validations...)
		Expect(err).NotTo(HaveOccurred())

		By("Checking that the secret contains this dns name")
		err = f.Helper().ValidateCertificate(cert, func(cert *v1.Certificate, secret *corev1.Secret) error {
			dnsnames, err := findDNSNames(secret)
			if err != nil {
				return err
			}
			Expect(cert.Spec.DNSNames).To(ContainElements(dnsnames))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to obtain a certificate for a blocked ACME dns name", func() {
		By("Creating a Certificate")
		// In "make/config/pebble/chart/templates/configmap.yaml"
		// the "google.com" domain is configured in the pebble blocklist.
		cert := gen.Certificate(certificateName,
			gen.SetCertificateNamespace(f.Namespace.Name),
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames("google.com"),
		)
		cert, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(ctx, cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		notReadyCondition := v1.CertificateCondition{
			Type:   v1.CertificateConditionReady,
			Status: cmmeta.ConditionFalse,
		}
		Eventually(cert, "30s", "1s").Should(HaveCondition(f, notReadyCondition))
		Consistently(cert, "1m", "10s").Should(HaveCondition(f, notReadyCondition))
	})

	It("should obtain a signed certificate with a single CN from the ACME server when putting an annotation on an ingress resource", func() {

		switch {
		case util.HasIngresses(f.KubeClientSet.Discovery(), networkingv1.SchemeGroupVersion.String()):
			ingClient := f.KubeClientSet.NetworkingV1().Ingresses(f.Namespace.Name)
			By("Creating an Ingress with the issuer name annotation set")
			_, err := ingClient.Create(ctx, util.NewIngress(certificateSecretName, certificateSecretName, map[string]string{
				"cert-manager.io/issuer": issuerName,
			}, acmeIngressDomain), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		case util.HasIngresses(f.KubeClientSet.Discovery(), networkingv1beta1.SchemeGroupVersion.String()):
			ingClient := f.KubeClientSet.NetworkingV1beta1().Ingresses(f.Namespace.Name)
			By("Creating an Ingress with the issuer name annotation set")
			_, err := ingClient.Create(ctx, util.NewV1Beta1Ingress(certificateSecretName, certificateSecretName, map[string]string{
				"cert-manager.io/issuer": issuerName,
			}, acmeIngressDomain), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		default:
			Fail("Neither " + networkingv1.SchemeGroupVersion.String() + " nor " + networkingv1beta1.SchemeGroupVersion.String() + " were discovered in the API server")
		}

		By("Waiting for Certificate to exist")
		cert, err := f.Helper().WaitForCertificateToExist(ctx, f.Namespace.Name, certificateSecretName, time.Second*60)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(cert, validations...)
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
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for (selfsign) Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		const dummycert = "dummy-tls"
		const secretname = "dummy-tls-secret"

		selfcert := gen.Certificate(dummycert,
			gen.SetCertificateNamespace(f.Namespace.Name),
			gen.SetCertificateSecretName(secretname),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{
				Name: "selfsign",
				Kind: v1.IssuerKind,
			}),
			gen.SetCertificateCommonName(acmeIngressDomain),
			gen.SetCertificateOrganization("test-org"),
			gen.SetCertificateDNSNames(acmeIngressDomain),
		)
		selfcert, err = certClient.Create(ctx, selfcert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		selfcert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, selfcert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(selfcert, validations...)
		Expect(err).NotTo(HaveOccurred())

		// create an ingress that points at nothing, but has the TLS redirect annotation set
		// using the TLS secret that we just got from the self-sign

		switch {
		case util.HasIngresses(f.KubeClientSet.Discovery(), networkingv1.SchemeGroupVersion.String()):
			ingress := f.KubeClientSet.NetworkingV1().Ingresses(f.Namespace.Name)
			_, err = ingress.Create(ctx, &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name: fixedIngressName,
					Annotations: map[string]string{
						"nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr.To("nginx"),
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{acmeIngressDomain},
							SecretName: secretname,
						},
					},
					Rules: []networkingv1.IngressRule{
						{
							Host: acmeIngressDomain,
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: func() *networkingv1.PathType { s := networkingv1.PathTypePrefix; return &s }(),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "doesnotexist",
													Port: networkingv1.ServiceBackendPort{
														Number: 443,
													},
												},
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
		case util.HasIngresses(f.KubeClientSet.Discovery(), networkingv1beta1.SchemeGroupVersion.String()):
			ingress := f.KubeClientSet.NetworkingV1beta1().Ingresses(f.Namespace.Name)
			_, err = ingress.Create(ctx, &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name: fixedIngressName,
					Annotations: map[string]string{
						"nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
					},
				},
				Spec: networkingv1beta1.IngressSpec{
					IngressClassName: ptr.To("nginx"),
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
		default:
			Fail("Neither " + networkingv1.SchemeGroupVersion.String() + " nor " + networkingv1beta1.SchemeGroupVersion.String() + " were discovered in the API server")
		}

		// This is a special cert for the test suite, where we specify an ingress rather than a
		// class
		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateNamespace(f.Namespace.Name),
			gen.AddCertificateLabels(map[string]string{
				"testing.cert-manager.io/fixed-ingress": "true",
			}),
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(acmeIngressDomain),
		)
		cert, err = certClient.Create(ctx, cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(cert, validations...)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should automatically recreate challenge pod and still obtain a certificate if it is manually deleted", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateNamespace(f.Namespace.Name),
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(acmeIngressDomain),
		)
		_, err := certClient.Create(ctx, cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("killing the solver pod")
		podClient := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name)
		var pod corev1.Pod
		logf, done := log.LogBackoff()
		defer done()
		err = wait.PollUntilContextTimeout(ctx, 1*time.Second, time.Minute*3, true, func(ctx context.Context) (bool, error) {
			logf("Waiting for solver pod to exist")
			podlist, err := podClient.List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, err
			}

			for _, p := range podlist.Items {
				logf("solver pod %s", p.Name)
				// TODO(dmo): make this cleaner instead of just going by name
				if strings.Contains(p.Name, "http-solver") {
					pod = p
					return true, nil
				}
			}
			return false, nil

		})
		Expect(err).NotTo(HaveOccurred())

		err = podClient.Delete(ctx, pod.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Certificate to exist")
		cert, err = f.Helper().WaitForCertificateToExist(ctx, f.Namespace.Name, certificateName, time.Second*60)
		Expect(err).NotTo(HaveOccurred())

		// The pod should get remade and the certificate should be made valid.
		// Killing the pod could potentially make the validation invalid if pebble
		// were to ask us for the challenge after the pod was killed, but because
		// we kill it so early, we should always be in the self-check phase
		By("Waiting for the Certificate to be issued...")
		cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(cert, validations...)
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
