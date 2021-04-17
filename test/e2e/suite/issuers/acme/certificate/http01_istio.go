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

package certificate

import (
	"context"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
	frameworkutil "github.com/jetstack/cert-manager/test/e2e/framework/util"
	"github.com/jetstack/cert-manager/test/e2e/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

const istioTestingACMEEmail = "e2e@cert-manager.io"
const istioTestingACMEPrivateKey = "test-acme-private-key"
const istioForeverTestTimeout = time.Second * 60

var _ = framework.CertManagerDescribe("ACME Certificate (HTTP01) Istio", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-http01-istio")

	var acmeIngressDomain string
	issuerName := "test-acme-issuer"
	certificateName := "test-acme-certificate"
	certificateSecretName := "test-acme-certificate"

	// ACME Issuer does not return a ca.crt. See:
	// https://github.com/jetstack/cert-manager/issues/1571
	unsupportedFeatures := featureset.NewFeatureSet(featureset.SaveCAToSecret)
	validations := f.Helper().ValidationSetForUnsupportedFeatureSet(unsupportedFeatures)

	BeforeEach(func() {
		solvers := []cmacme.ACMEChallengeSolver{
			{
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Istio: &cmacme.ACMEChallengeSolverHTTP01Istio{
						GatewayNamespace: f.Config.Addons.Istio.GatewayNamespace,
						GatewayName:      f.Config.Addons.Istio.GatewayName,
					},
				},
			},
		}
		acmeIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerACMEEmail(istioTestingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMEPrivKeyRef(istioTestingACMEPrivateKey),
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
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), istioTestingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}
	})

	JustBeforeEach(func() {
		acmeIngressDomain = frameworkutil.RandomSubdomain(f.Config.Addons.Istio.Domain)
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuerName, metav1.DeleteOptions{})
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), istioTestingACMEPrivateKey, metav1.DeleteOptions{})
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
		By("Waiting for the Certificate to be issued...")
		err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, validations...)
		Expect(err).NotTo(HaveOccurred())
	})
})
