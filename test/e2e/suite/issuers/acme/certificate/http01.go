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
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	ext "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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

const invalidACMEURL = "http://not-a-real-acme-url.com"
const testingACMEEmail = "e2e@cert-manager.io"
const testingACMEPrivateKey = "test-acme-private-key"
const foreverTestTimeout = time.Second * 60

var _ = framework.CertManagerDescribe("ACME Certificate (HTTP01)", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-http01")
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
	certificateName := "test-acme-certificate"
	certificateSecretName := "test-acme-certificate"

	BeforeEach(func() {
		acmeURL := pebble.Details().Host
		acmeIssuer := util.NewCertManagerACMEIssuer(issuerName, acmeURL, testingACMEEmail, testingACMEPrivateKey)

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
		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		_, err := certClient.Create(util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil, acmeIngressClass, acmeIngressDomain))
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the Certificate is valid")
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate for a long domain using http01 validation", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

		// the maximum length of a single segment of the domain being requested
		const maxLengthOfDomainSegment = 63
		By("Creating a Certificate")
		_, err := certClient.Create(util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil, acmeIngressClass, fmt.Sprintf("%s.%s", cmutil.RandStringRunes(maxLengthOfDomainSegment), acmeIngressDomain)))
		Expect(err).NotTo(HaveOccurred())
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with a CN and single subdomain as dns name from the ACME server", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		_, err := certClient.Create(util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil, acmeIngressClass, acmeIngressDomain, fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)))
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the Certificate is valid")
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow updating an existing certificate with a new dns name", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert, err := certClient.Create(util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil, acmeIngressClass, acmeIngressDomain, fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)))
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the Certificate is valid")
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Getting the latest version of the Certificate")
		cert, err = certClient.Get(certificateName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Adding an additional dnsName to the Certificate")
		newDNSName := fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeIngressDomain)
		cert.Spec.DNSNames = append(cert.Spec.DNSNames, newDNSName)
		cert.Spec.ACME.Config[0].Domains = append(cert.Spec.ACME.Config[0].Domains, newDNSName)

		By("Updating the Certificate in the apiserver")
		cert, err = certClient.Update(cert)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be not ready")
		_, err = h.WaitForCertificateNotReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to become ready & valid")
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to obtain a certificate for an invalid ACME dns name", func() {
		// create test fixture
		cert := util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil, acmeIngressClass, "google.com")
		cert, err := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(cert)
		Expect(err).NotTo(HaveOccurred())

		notReadyCondition := v1alpha1.CertificateCondition{
			Type:   v1alpha1.CertificateConditionReady,
			Status: v1alpha1.ConditionFalse,
		}
		Eventually(cert, "30s", "1s").Should(HaveCondition(f, notReadyCondition))
		Consistently(cert, "1m", "10s").Should(HaveCondition(f, notReadyCondition))
	})

	It("should obtain a signed certificate with a single CN from the ACME server when putting an annotation on an ingress resource", func() {
		ingClient := f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace.Name)
		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

		By("Creating an Ingress with the issuer name annotation set")
		_, err := ingClient.Create(util.NewIngress(certificateSecretName, certificateSecretName, map[string]string{
			"certmanager.k8s.io/issuer":                  issuerName,
			"certmanager.k8s.io/acme-challenge-provider": "http01",
		}, acmeIngressDomain))
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Certificate to exist")
		err = util.WaitForCertificateToExist(certClient, certificateSecretName, foreverTestTimeout)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the Certificate is valid")
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with a single CN from the ACME server when redirected", func() {

		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

		// force-ssl-redirect should make every request turn into a redirect,
		// but I haven't been able to make this happen. Create a TLS cert via
		// the self-sign issuer to make it have a "proper" TLS cert

		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerSelfSignedIssuer("selfsign"))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for (self-sign) Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		const dummycert = "dummy-tls"
		const secretname = "dummy-tls-secret"
		selfcert := util.NewCertManagerBasicCertificate("dummy-tls", secretname, "selfsign", v1alpha1.IssuerKind, nil, nil)
		selfcert.Spec.CommonName = acmeIngressDomain
		_, err = certClient.Create(selfcert)
		Expect(err).NotTo(HaveOccurred())
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, dummycert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		// create an ingress that points at nothing, but has the TLS redirect annotation set
		// using the TLS secret that we just got from the self-sign
		const ingressname = "httpsingress"
		ingress := f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace.Name)
		_, err = ingress.Create(&ext.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name: ingressname,
				Annotations: map[string]string{
					"nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
					"kubernetes.io/ingress.class":                    "nginx",
				},
			},
			Spec: ext.IngressSpec{
				TLS: []ext.IngressTLS{
					{
						Hosts:      []string{acmeIngressDomain},
						SecretName: secretname,
					},
				},
				Rules: []ext.IngressRule{
					{
						Host: acmeIngressDomain,
						IngressRuleValue: ext.IngressRuleValue{
							HTTP: &ext.HTTPIngressRuleValue{
								Paths: []ext.HTTPIngressPath{
									{
										Path: "/",
										Backend: ext.IngressBackend{
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
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating a Certificate")
		// This is a special cert for the test suite, where we specify an ingress rather than a
		// class
		cert := util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil, acmeIngressClass, acmeIngressDomain)
		http01 := cert.Spec.ACME.Config[0].SolverConfig.HTTP01
		http01.IngressClass = nil
		http01.Ingress = ingressname

		_, err = certClient.Create(cert)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the Certificate is valid")
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should automatically recreate challenge pod and still obtain a certificate if it is manually deleted", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		_, err := certClient.Create(util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil, acmeIngressClass, acmeIngressDomain))
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
		By("Verifying the Certificate is valid")
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())
	})

})
