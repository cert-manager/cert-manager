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

package selfsigned

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// This test ensures that a self-signed certificaterequest will still be signed
// even if the private key Secret was created _after_ the CertificateRequest
// was created.
var _ = framework.CertManagerDescribe("CertificateRequests SelfSigned Secret", func() {
	f := framework.NewDefaultFramework("certificaterequests-selfsigned-secret")

	var (
		request *cmapi.CertificateRequest
		issuer  cmapi.GenericIssuer
		secret  *corev1.Secret
		bundle  *testcrypto.CryptoBundle
	)

	JustBeforeEach(func() {
		var err error
		bundle, err = testcrypto.CreateCryptoBundle(&cmapi.Certificate{
			Spec: cmapi.CertificateSpec{
				CommonName: "selfsigned-test",
			},
		}, clock.RealClock{})
		Expect(err).NotTo(HaveOccurred())
	})

	JustAfterEach(func() {
		Expect(f.CRClient.Delete(context.TODO(), request)).NotTo(HaveOccurred())
		Expect(f.CRClient.Delete(context.TODO(), issuer)).NotTo(HaveOccurred())
		Expect(f.CRClient.Delete(context.TODO(), secret)).NotTo(HaveOccurred())
	})

	It("Issuer: the private key Secret is created after the request is created should still be signed", func() {
		var err error
		issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), &cmapi.Issuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "selfsigned-", Namespace: f.Namespace.Name},
			Spec:       cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{SelfSigned: new(cmapi.SelfSignedIssuer)}},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Create(context.TODO(), &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "selfsigned-", Namespace: f.Namespace.Name,
				Annotations: map[string]string{"cert-manager.io/private-key-secret-name": "selfsigned-test"},
			},
			Spec: cmapi.CertificateRequestSpec{
				Request:   bundle.CSRBytes,
				IssuerRef: cmmeta.ObjectReference{Name: issuer.GetName(), Kind: "Issuer", Group: "cert-manager.io"},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for request to be set to pending")
		Eventually(func() bool {
			request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return apiutil.CertificateRequestHasCondition(request, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionFalse,
				Reason: cmapi.CertificateRequestReasonPending,
			})
		}, "20s", "1s").Should(BeTrue(), "request was not set to pending in time: %#+v", request)

		By("creating Secret with private key should result in the request to be signed")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "selfsigned-test", Namespace: f.Namespace.Name},
			Data: map[string][]byte{
				"tls.key": bundle.PrivateKeyBytes,
			},
		}, metav1.CreateOptions{})

		Eventually(func() bool {
			request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return apiutil.CertificateRequestHasCondition(request, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
				Reason: cmapi.CertificateRequestReasonIssued,
			}) && len(request.Status.Certificate) > 0
		}, "20s", "1s").Should(BeTrue(), "request was not signed in time: %#+v", request)
	})

	It("Issuer: private key Secret is updated with a valid private key after the request is created should still be signed", func() {
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

		request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Create(context.TODO(), &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "selfsigned-", Namespace: f.Namespace.Name,
				Annotations: map[string]string{"cert-manager.io/private-key-secret-name": "selfsigned-test"},
			},
			Spec: cmapi.CertificateRequestSpec{
				Request:   bundle.CSRBytes,
				IssuerRef: cmmeta.ObjectReference{Name: issuer.GetName(), Kind: "Issuer", Group: "cert-manager.io"},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for request to be set to pending")
		Eventually(func() bool {
			request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return apiutil.CertificateRequestHasCondition(request, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionFalse,
				Reason: cmapi.CertificateRequestReasonPending,
			})
		}, "20s", "1s").Should(BeTrue(), "request was not set to pending in time: %#+v", request)

		By("updating referenced private key Secret should get the request signed")
		secret.Data = map[string][]byte{"tls.key": bundle.PrivateKeyBytes}
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(context.TODO(), secret, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool {
			request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return apiutil.CertificateRequestHasCondition(request, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
				Reason: cmapi.CertificateRequestReasonIssued,
			}) && len(request.Status.Certificate) > 0
		}, "20s", "1s").Should(BeTrue(), "request was not signed in time: %#+v", request)
	})

	It("ClusterIssuer: the private key Secret is created after the request is created should still be signed", func() {
		var err error
		issuer, err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), &cmapi.ClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "selfsigned-"},
			Spec:       cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{SelfSigned: new(cmapi.SelfSignedIssuer)}},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Create(context.TODO(), &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "selfsigned-", Namespace: f.Namespace.Name,
				Annotations: map[string]string{"cert-manager.io/private-key-secret-name": "selfsigned-test"},
			},
			Spec: cmapi.CertificateRequestSpec{
				Request:   bundle.CSRBytes,
				IssuerRef: cmmeta.ObjectReference{Name: issuer.GetName(), Kind: "ClusterIssuer", Group: "cert-manager.io"},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for request to be set to pending")
		Eventually(func() bool {
			request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return apiutil.CertificateRequestHasCondition(request, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionFalse,
				Reason: cmapi.CertificateRequestReasonPending,
			})
		}, "20s", "1s").Should(BeTrue(), "request was not set to pending in time: %#+v", request)

		By("creating Secret with private key should result in the request to be signed")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "selfsigned-test", Namespace: f.Namespace.Name},
			Data: map[string][]byte{
				"tls.key": bundle.PrivateKeyBytes,
			},
		}, metav1.CreateOptions{})

		Eventually(func() bool {
			request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return apiutil.CertificateRequestHasCondition(request, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
				Reason: cmapi.CertificateRequestReasonIssued,
			}) && len(request.Status.Certificate) > 0
		}, "20s", "1s").Should(BeTrue(), "request was not signed in time: %#+v", request)
	})

	It("ClusterIssuer: private key Secret is updated with a valid private key after the request is created should still be signed", func() {
		var err error
		By("creating Secret with missing private key")
		secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "selfsigned-test", Namespace: f.Namespace.Name},
			Data:       map[string][]byte{},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		issuer, err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), &cmapi.ClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "selfsigned-"},
			Spec:       cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{SelfSigned: new(cmapi.SelfSignedIssuer)}},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Create(context.TODO(), &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "selfsigned-", Namespace: f.Namespace.Name,
				Annotations: map[string]string{"cert-manager.io/private-key-secret-name": "selfsigned-test"},
			},
			Spec: cmapi.CertificateRequestSpec{
				Request:   bundle.CSRBytes,
				IssuerRef: cmmeta.ObjectReference{Name: issuer.GetName(), Kind: "ClusterIssuer", Group: "cert-manager.io"},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for request to be set to pending")
		Eventually(func() bool {
			request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return apiutil.CertificateRequestHasCondition(request, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionFalse,
				Reason: cmapi.CertificateRequestReasonPending,
			})
		}, "20s", "1s").Should(BeTrue(), "request was not set to pending in time: %#+v", request)

		By("updating referenced private key Secret should get the request signed")
		secret.Data = map[string][]byte{"tls.key": bundle.PrivateKeyBytes}
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(context.TODO(), secret, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool {
			request, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return apiutil.CertificateRequestHasCondition(request, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
				Reason: cmapi.CertificateRequestReasonIssued,
			}) && len(request.Status.Certificate) > 0
		}, "20s", "1s").Should(BeTrue(), "request was not signed in time: %#+v", request)
	})
})
