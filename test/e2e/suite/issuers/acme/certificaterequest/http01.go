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

package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmutil "github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/pebble"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
	. "github.com/jetstack/cert-manager/test/e2e/framework/matcher"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

var _ = framework.CertManagerDescribe("ACME CertificateRequest (HTTP01)", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-request-http01")
	h := f.Helper()

	var (
		tiller = &tiller.Tiller{
			Name:               "tiller-deploy",
			ClusterPermissions: false,
		}
		pebble = &pebble.Pebble{
			Tiller: tiller,
			Name:   "cm-e2e-create-acme-issuer",
		}
	)

	BeforeEach(func() {
		tiller.Namespace = f.Namespace.Name
		pebble.Namespace = f.Namespace.Name
	})

	f.RequireGlobalAddon(addon.NginxIngress)
	f.RequireAddon(tiller)
	f.RequireAddon(pebble)

	var acmeIngressDomain string
	var acmeIngressClass string
	issuerName := "test-acme-issuer"
	certificateRequestName := "test-acme-certificate-request"
	// fixedIngressName is the name of an ingress resource that is configured
	// with a challenge solve.
	// To utilise this solver, add the 'testing.cert-manager.io/fixed-ingress: "true"' label.
	fixedIngressName := "testingress"

	BeforeEach(func() {
		acmeURL := pebble.Details().Host
		acmeIssuer := util.NewCertManagerACMEIssuer(issuerName, acmeURL, testingACMEEmail, testingACMEPrivateKey)
		acmeIssuer.Spec.ACME.HTTP01 = nil
		acmeIssuer.Spec.ACME.Solvers = []v1alpha1.ACMEChallengeSolver{
			{
				HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
					Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
						Class: &addon.NginxIngress.Details().IngressClass,
					},
				},
			},
			{
				Selector: &v1alpha1.CertificateDNSNameSelector{
					MatchLabels: map[string]string{
						"testing.cert-manager.io/fixed-ingress": "true",
					},
				},
				HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
					Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
						Name: fixedIngressName,
					},
				},
			},
		}
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(acmeIssuer)
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			func(i *v1alpha1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(testingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}
	})

	JustBeforeEach(func() {
		acmeIngressDomain = addon.NginxIngress.Details().NewTestDomain()
		acmeIngressClass = addon.NginxIngress.Details().IngressClass
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(testingACMEPrivateKey, nil)
	})

	It("should obtain a signed certificate with a single CN from the ACME server", func() {
		crClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

		By("Creating a CertificateRequest")
		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind, nil,
			[]string{acmeIngressDomain}, nil, nil, x509.RSA)
		Expect(err).NotTo(HaveOccurred())

		cr, err = crClient.Create(cr)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the Certificate is valid")
		err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Minute*5, key)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed ecdsa certificate with a single CN from the ACME server", func() {
		crClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

		By("Creating a CertificateRequest")
		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind, nil,
			[]string{acmeIngressDomain}, nil, nil, x509.ECDSA)
		Expect(err).NotTo(HaveOccurred())

		_, err = crClient.Create(cr)
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the Certificate is valid and of type ECDSA")
		err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Minute*5, key)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate for a long domain using http01 validation", func() {
		crClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

		// the maximum length of a single segment of the domain being requested
		const maxLengthOfDomainSegment = 63
		By("Creating a CertificateRequest")
		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind, nil,
			[]string{acmeIngressDomain, fmt.Sprintf("%s.%s", cmutil.RandStringRunes(maxLengthOfDomainSegment), acmeIngressDomain)},
			nil, nil, x509.RSA)
		Expect(err).NotTo(HaveOccurred())

		_, err = crClient.Create(cr)
		Expect(err).NotTo(HaveOccurred())
		err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Minute*5, key)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with a CN and single subdomain as dns name from the ACME server", func() {
		crClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

		By("Creating a CertificateRequest")
		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind, nil,
			[]string{fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)},
			nil, nil, x509.RSA)
		Expect(err).NotTo(HaveOccurred())

		_, err = crClient.Create(cr)
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the CertificateRequest is valid")
		err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Minute*5, key)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to obtain a certificate for an invalid ACME dns name", func() {
		// create test fixture
		By("Creating a CertificateRequest")
		cr, _, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind, nil,
			[]string{"google.com"}, nil, nil, x509.RSA)
		Expect(err).NotTo(HaveOccurred())

		cr, err = f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name).Create(cr)
		Expect(err).NotTo(HaveOccurred())

		notReadyCondition := v1alpha1.CertificateRequestCondition{
			Type:   v1alpha1.CertificateRequestConditionReady,
			Status: v1alpha1.ConditionFalse,
		}
		Eventually(cr, "30s", "1s").Should(HaveCondition(f, notReadyCondition))
		Consistently(cr, "1m", "10s").Should(HaveCondition(f, notReadyCondition))
	})

	It("should automatically recreate challenge pod and still obtain a certificate if it is manually deleted", func() {
		crClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

		By("Creating a CertificateRequest")
		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind, nil,
			[]string{acmeIngressDomain}, nil, nil, x509.RSA)
		Expect(err).NotTo(HaveOccurred())

		_, err = crClient.Create(cr)
		Expect(err).NotTo(HaveOccurred())

		By("killing the solver pod")
		podClient := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name)
		var pod corev1.Pod
		err = wait.PollImmediate(1*time.Second, time.Minute,
			func() (bool, error) {
				log.Logf("Waiting for solver pod to exist")
				podlist, err := podClient.List(metav1.ListOptions{})
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

		err = podClient.Delete(pod.Name, &metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// The pod should get remade and the certificate should be made valid.
		// Killing the pod could potentially make the validation invalid if pebble
		// were to ask us for the challenge after the pod was killed, but because
		// we kill it so early, we should always be in the self-check phase
		By("Verifying the CertificateRequest is valid")
		err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Minute*5, key)
		Expect(err).NotTo(HaveOccurred())
	})
})
