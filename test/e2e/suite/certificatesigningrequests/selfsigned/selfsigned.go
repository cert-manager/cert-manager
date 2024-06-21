/*
Copyright 2022 The cert-manager Authors.

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

package selfsigned

import (
	"context"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// This test ensures that a self-signed certificatesigningrequests will still
// be signed, even if the private key Secret was created _after_ the
// CertificateSigningRequest was created.
var _ = framework.CertManagerDescribe("CertificateSigningRequests SelfSigned Secret", func() {
	f := framework.NewDefaultFramework("certificatesigningrequests-selfsigned-secret")

	var (
		request *certificatesv1.CertificateSigningRequest
		issuer  cmapi.GenericIssuer
		secret  *corev1.Secret
		bundle  *testcrypto.CryptoBundle
	)

	JustBeforeEach(func() {
		var err error
		bundle, err = testcrypto.CreateCryptoBundle(&cmapi.Certificate{
			Spec: cmapi.CertificateSpec{CommonName: "selfsigned-test"}}, clock.RealClock{})
		Expect(err).NotTo(HaveOccurred())
	})

	JustAfterEach(func() {
		Expect(f.CRClient.Delete(context.TODO(), request)).NotTo(HaveOccurred())
		Expect(f.CRClient.Delete(context.TODO(), issuer)).NotTo(HaveOccurred())
		Expect(f.CRClient.Delete(context.TODO(), secret)).NotTo(HaveOccurred())
	})

	It("Issuer: the private key Secret is created after the request is created should still be signed", func() {
		framework.RequireFeatureGate(utilfeature.DefaultFeatureGate, feature.ExperimentalCertificateSigningRequestControllers)

		var err error
		issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), &cmapi.Issuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "selfsigned-", Namespace: f.Namespace.Name},
			Spec:       cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{SelfSigned: new(cmapi.SelfSignedIssuer)}},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("creating request")
		request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), &certificatesv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "selfsigned-",
				Annotations:  map[string]string{"experimental.cert-manager.io/private-key-secret-name": "selfsigned-test"},
			},
			Spec: certificatesv1.CertificateSigningRequestSpec{
				Request:    bundle.CSRBytes,
				SignerName: fmt.Sprintf("issuers.cert-manager.io/%s.%s", f.Namespace.Name, issuer.GetName()),
				Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageKeyEncipherment, certificatesv1.UsageDigitalSignature},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("approving request")
		request.Status.Conditions = append(request.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue,
			Reason: "Approved", Message: "approved for cert-manager.io selfigned e2e test",
			LastUpdateTime: metav1.NewTime(time.Now()), LastTransitionTime: metav1.NewTime(time.Now()),
		})
		request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), request.Name, request, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for request to have SecretNotFound event")
		Eventually(func() bool {
			events, err := f.KubeClientSet.EventsV1().Events("default").List(context.TODO(), metav1.ListOptions{
				FieldSelector: "reason=SecretNotFound,type=Warning",
			})
			Expect(err).NotTo(HaveOccurred())
			for _, event := range events.Items {
				if event.Regarding.UID == request.UID {
					return true
				}
			}
			return false
		}, "20s", "1s").Should(BeTrue(), "SecretNotFound event not found for request")

		By("creating Secret with private key should result in the request to be signed")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "selfsigned-test", Namespace: f.Namespace.Name},
			Data: map[string][]byte{
				"tls.key": bundle.PrivateKeyBytes,
			},
		}, metav1.CreateOptions{})

		Eventually(func() bool {
			request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return len(request.Status.Certificate) > 0
		}, "20s", "1s").Should(BeTrue(), "request was not signed in time: %#+v", request)
	})

	It("Issuer: private key Secret is updated with a valid private key after the request is created should still be signed", func() {
		framework.RequireFeatureGate(utilfeature.DefaultFeatureGate, feature.ExperimentalCertificateSigningRequestControllers)

		var err error
		By("creating Secret with missing private key")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "selfsigned-test", Namespace: f.Namespace.Name},
			Data:       map[string][]byte{},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), &cmapi.Issuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "selfsigned-", Namespace: f.Namespace.Name},
			Spec:       cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{SelfSigned: new(cmapi.SelfSignedIssuer)}},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("creating request")
		request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), &certificatesv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "selfsigned-",
				Annotations:  map[string]string{"experimental.cert-manager.io/private-key-secret-name": "selfsigned-test"},
			},
			Spec: certificatesv1.CertificateSigningRequestSpec{
				Request:    bundle.CSRBytes,
				SignerName: fmt.Sprintf("issuers.cert-manager.io/%s.%s", f.Namespace.Name, issuer.GetName()),
				Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageKeyEncipherment, certificatesv1.UsageDigitalSignature},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("approving request")
		request.Status.Conditions = append(request.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue,
			Reason: "Approved", Message: "approved for cert-manager.io selfigned e2e test",
			LastUpdateTime: metav1.NewTime(time.Now()), LastTransitionTime: metav1.NewTime(time.Now()),
		})
		request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), request.Name, request, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for request to have ErrorParsingKey event")
		Eventually(func() bool {
			events, err := f.KubeClientSet.EventsV1().Events("default").List(context.TODO(), metav1.ListOptions{
				FieldSelector: "reason=ErrorParsingKey,type=Warning",
			})
			Expect(err).NotTo(HaveOccurred())
			for _, event := range events.Items {
				if event.Regarding.UID == request.UID {
					return true
				}
			}
			return false
		}, "20s", "1s").Should(BeTrue(), "ErrorParsingKey event not found for request")

		By("updating referenced private key Secret should get the request signed")
		secret.Data = map[string][]byte{"tls.key": bundle.PrivateKeyBytes}
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(context.TODO(), secret, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool {
			request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return len(request.Status.Certificate) > 0
		}, "20s", "1s").Should(BeTrue(), "request was not signed in time: %#+v", request)
	})

	It("ClusterIssuer: the private key Secret is created after the request is created should still be signed", func() {
		framework.RequireFeatureGate(utilfeature.DefaultFeatureGate, feature.ExperimentalCertificateSigningRequestControllers)

		var err error
		issuer, err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), &cmapi.ClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "selfsigned-"},
			Spec:       cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{SelfSigned: new(cmapi.SelfSignedIssuer)}},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("creating request")
		request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), &certificatesv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "selfsigned-",
				Annotations:  map[string]string{"experimental.cert-manager.io/private-key-secret-name": "selfsigned-test"},
			},
			Spec: certificatesv1.CertificateSigningRequestSpec{
				Request:    bundle.CSRBytes,
				SignerName: fmt.Sprintf("clusterissuers.cert-manager.io/" + issuer.GetName()),
				Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageKeyEncipherment, certificatesv1.UsageDigitalSignature},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("approving request")
		request.Status.Conditions = append(request.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue,
			Reason: "Approved", Message: "approved for cert-manager.io selfigned e2e test",
			LastUpdateTime: metav1.NewTime(time.Now()), LastTransitionTime: metav1.NewTime(time.Now()),
		})
		request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), request.Name, request, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for request to have SecretNotFound event")
		Eventually(func() bool {
			events, err := f.KubeClientSet.EventsV1().Events("default").List(context.TODO(), metav1.ListOptions{
				FieldSelector: "reason=SecretNotFound,type=Warning",
			})
			Expect(err).NotTo(HaveOccurred())
			for _, event := range events.Items {
				if event.Regarding.UID == request.UID {
					return true
				}
			}
			return false
		}, "20s", "1s").Should(BeTrue(), "SecretNotFound event not found for request")

		By("creating Secret with private key should result in the request to be signed")
		secret, err = f.KubeClientSet.CoreV1().Secrets("cert-manager").Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "selfsigned-test", Namespace: "cert-manager"},
			Data: map[string][]byte{
				"tls.key": bundle.PrivateKeyBytes,
			},
		}, metav1.CreateOptions{})

		Eventually(func() bool {
			request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return len(request.Status.Certificate) > 0
		}, "20s", "1s").Should(BeTrue(), "request was not signed in time: %#+v", request)
	})

	It("ClusterIssuer: private key Secret is updated with a valid private key after the request is created should still be signed", func() {
		framework.RequireFeatureGate(utilfeature.DefaultFeatureGate, feature.ExperimentalCertificateSigningRequestControllers)

		var err error
		By("creating Secret with missing private key")
		secret, err = f.KubeClientSet.CoreV1().Secrets("cert-manager").Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "selfsigned-test", Namespace: "cert-manager"},
			Data:       map[string][]byte{},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuer, err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), &cmapi.ClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "selfsigned-"},
			Spec:       cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{SelfSigned: new(cmapi.SelfSignedIssuer)}},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("creating request")
		request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), &certificatesv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "selfsigned-",
				Annotations:  map[string]string{"experimental.cert-manager.io/private-key-secret-name": "selfsigned-test"},
			},
			Spec: certificatesv1.CertificateSigningRequestSpec{
				Request:    bundle.CSRBytes,
				SignerName: fmt.Sprintf("clusterissuers.cert-manager.io/" + issuer.GetName()),
				Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageKeyEncipherment, certificatesv1.UsageDigitalSignature},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("approving request")
		request.Status.Conditions = append(request.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue,
			Reason: "Approved", Message: "approved for cert-manager.io selfigned e2e test",
			LastUpdateTime: metav1.NewTime(time.Now()), LastTransitionTime: metav1.NewTime(time.Now()),
		})
		request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), request.Name, request, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for request to have ErrorParsingKey event")
		Eventually(func() bool {
			events, err := f.KubeClientSet.EventsV1().Events("default").List(context.TODO(), metav1.ListOptions{
				FieldSelector: "reason=ErrorParsingKey,type=Warning",
			})
			Expect(err).NotTo(HaveOccurred())
			for _, event := range events.Items {
				if event.Regarding.UID == request.UID {
					return true
				}
			}
			return false
		}, "20s", "1s").Should(BeTrue(), "ErrorParsingKey event not found for request")

		By("updating referenced private key Secret should get the request signed")
		secret.Data = map[string][]byte{"tls.key": bundle.PrivateKeyBytes}
		_, err = f.KubeClientSet.CoreV1().Secrets("cert-manager").Update(context.TODO(), secret, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool {
			request, err = f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return len(request.Status.Certificate) > 0
		}, "20s", "1s").Should(BeTrue(), "request was not signed in time: %#+v", request)
	})
})
