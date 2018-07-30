package certificate

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/util"
	"github.com/jetstack/cert-manager/test/util/cfssl"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	issuerAuthKeySecret     = "C0DEC0DEC0DEC0DEC0DEC0DE"
	issuerAuthKeySecretName = "test-cfssl-authkey"
)

var _ = framework.CertManagerDescribe("CFSSL Certificate (issuer has no authkey)", func() {
	f := framework.NewDefaultFramework("create-cfssl-certificate")

	issuerName := "test-cfssl-issuer-no-authkey"

	releaseName := "cfssl-no-auth"
	releaseSecretName := fmt.Sprintf("%s-cfssl", releaseName)

	BeforeEach(func() {
		secretClient := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name)

		By("Verifying there is no existing authkey secret")
		_, err := secretClient.Get(issuerAuthKeySecretName, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), issuerAuthKeySecretName)))

		By("Creating a secret fixture for cfssl server pod")
		serverSecret, err := cfssl.NewCFSSLServerSecret(releaseSecretName, v1alpha1.ECDSAKeyAlgorithm, pki.ECCurve256)
		Expect(err).NotTo(HaveOccurred())
		_, err = secretClient.Create(serverSecret)
		Expect(err).NotTo(HaveOccurred())

		By("deploying a CFSSL server with authentication disabled")
		err = cfssl.InstallHelmChart(releaseName, f.Namespace.Name, "./test/fixtures/cfssl-without-auth-values.yaml")
		Expect(err).NotTo(HaveOccurred())

		By("Creating an Issuer")
		serverURL := fmt.Sprintf("http://%s-cfssl.%s:8080", releaseName, f.Namespace.Name)
		serverPath := "/api/v1/cfssl/sign"
		_, err = f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(
			util.NewCertManagerCFSSLIssuer(issuerName, serverURL, serverPath, ""),
		)
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(releaseSecretName, nil)

		err := cfssl.DeleteHelmChart(releaseName)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate from CFSSL server", func() {
		certificateName := "test-cfssl-certificate-1"
		certificateSecretName := "test-cfssl-secret-1"

		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)
		secretClient := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name)

		By("Verifying there is no existing TLS certificate secret")
		_, err := secretClient.Get(certificateSecretName, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), certificateSecretName)))

		By("Creating a Certificate with a custom profile")
		certificate := util.NewCertManagerCFSSLCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind)
		certificate.Spec.CFSSL = &v1alpha1.CFSSLCertificateConfig{
			Profile: "test-profile",
			Label:   "test-label",
		}
		_, err = certClient.Create(certificate)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the certificate is valid")
		err = util.WaitCertificateIssuedValid(certClient, secretClient, certificateName, 2*time.Minute)
		Expect(err).NotTo(HaveOccurred())

		certificateName = "test-cfssl-certificate-2"
		certificateSecretName = "test-cfssl-secret-2"

		By("Verifying there is no existing TLS certificate secret")
		_, err = secretClient.Get(certificateSecretName, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), certificateSecretName)))

		By("Creating a Certificate without a custom profile")
		certificate = util.NewCertManagerCFSSLCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind)
		certificate.Spec.CFSSL = nil
		_, err = certClient.Create(certificate)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the certificate is valid")
		err = util.WaitCertificateIssuedValid(certClient, secretClient, certificateName, 2*time.Minute)
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = framework.CertManagerDescribe("CFSSL Certificate (issuer has authkey)", func() {
	f := framework.NewDefaultFramework("create-cfssl-certificate")

	issuerName := "test-cfssl-issuer-with-authkey"

	releaseName := "cfssl-with-auth"
	releaseSecretName := fmt.Sprintf("%s-cfssl", releaseName)

	BeforeEach(func() {
		By("Verifying there is no existing authkey secret")
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(issuerAuthKeySecretName, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), issuerAuthKeySecretName)))

		By("Creating a authkey secret fixture")
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(cfssl.NewAuthKeySecret(issuerAuthKeySecretName, issuerAuthKeySecret))
		Expect(err).NotTo(HaveOccurred())

		By("Creating a secret fixture for cfssl server pod")
		serverSecret, err := cfssl.NewCFSSLServerSecret(releaseSecretName, v1alpha1.ECDSAKeyAlgorithm, pki.ECCurve256)
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(serverSecret)
		Expect(err).NotTo(HaveOccurred())

		By("deploying a CFSSL server with authentication enabled")
		err = cfssl.InstallHelmChart(releaseName, f.Namespace.Name, "./test/fixtures/cfssl-with-auth-values.yaml")
		Expect(err).NotTo(HaveOccurred())

		By("Creating an Issuer")
		serverURL := fmt.Sprintf("http://%s-cfssl.%s:8080", releaseName, f.Namespace.Name)
		serverPath := "/api/v1/cfssl/authsign"
		_, err = f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(
			util.NewCertManagerCFSSLIssuer(issuerName, serverURL, serverPath, issuerAuthKeySecretName),
		)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(issuerAuthKeySecretName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(releaseSecretName, nil)

		err := cfssl.DeleteHelmChart(releaseName)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate from CFSSL server", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)
		secretClient := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name)

		certificateName := "test-cfssl-certificate-with-authkey-1"
		certificateSecretName := "test-cfssl-secret-with-authkey-1"

		By("Verifying there is no existing TLS certificate secret")
		_, err := secretClient.Get(certificateSecretName, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), certificateSecretName)))

		By("Creating a Certificate with a custom profile")
		certificate := util.NewCertManagerCFSSLCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind)
		certificate.Spec.CFSSL = &v1alpha1.CFSSLCertificateConfig{
			Profile: "test-profile",
		}
		_, err = certClient.Create(certificate)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the certificate is valid")
		err = util.WaitCertificateIssuedValid(certClient, secretClient, certificateName, 2*time.Minute)
		Expect(err).NotTo(HaveOccurred())

		certificateName = "test-cfssl-certificate-with-authkey-2"
		certificateSecretName = "test-cfssl-secret-with-authkey-2"

		By("Verifying there is no existing TLS certificate secret")
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(certificateSecretName, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), certificateSecretName)))

		By("Creating a Certificate without a custom profile")
		certificate = util.NewCertManagerCFSSLCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind)
		certificate.Spec.CFSSL = nil
		_, err = certClient.Create(certificate)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the certificate is valid")
		err = util.WaitCertificateIssuedValid(certClient, secretClient, certificateName, 2*time.Minute)
		Expect(err).NotTo(HaveOccurred())
	})
})
