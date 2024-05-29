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

package selfsigned

import (
	"context"
	"crypto"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificatesigningrequests"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.ConformanceDescribe("CertificateSigningRequests", func() {
	(&certificatesigningrequests.Suite{
		Name:             "SelfSigned Issuer",
		CreateIssuerFunc: createSelfSignedIssuer,
		ProvisionFunc:    provision,
		DeProvisionFunc:  deProvision,
	}).Define()

	(&certificatesigningrequests.Suite{
		Name:             "SelfSigned ClusterIssuer",
		CreateIssuerFunc: createSelfSignedClusterIssuer,
		DeleteIssuerFunc: deleteSelfSignedClusterIssuer,
		ProvisionFunc:    provision,
		DeProvisionFunc:  deProvision,
	}).Define()
})

func provision(ctx context.Context, f *framework.Framework, csr *certificatesv1.CertificateSigningRequest, key crypto.Signer) {
	By("Creating SelfSigned requester key Secret")
	ref, _ := util.SignerIssuerRefFromSignerName(csr.Spec.SignerName)
	ns := "cert-manager"
	if kind, _ := util.IssuerKindFromType(ref.Type); kind == cmapi.IssuerKind {
		ns = ref.Namespace
	}

	keyPEM, err := pki.EncodePKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred(), "failed to encode requester's private key")

	secret, err := f.KubeClientSet.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-requester-key-",
			Namespace:    ns,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create requester's private key Secret")

	if csr.Annotations == nil {
		csr.Annotations = make(map[string]string)
	}
	csr.Annotations[experimentalapi.CertificateSigningRequestPrivateKeyAnnotationKey] = secret.Name
}
func deProvision(ctx context.Context, f *framework.Framework, csr *certificatesv1.CertificateSigningRequest) {
	By("Deleting SelfSigned requester key Secret")
	ref, _ := util.SignerIssuerRefFromSignerName(csr.Spec.SignerName)
	ns := f.Config.Addons.CertManager.ClusterResourceNamespace
	if kind, _ := util.IssuerKindFromType(ref.Type); kind == cmapi.IssuerKind {
		ns = ref.Namespace
	}

	err := f.KubeClientSet.CoreV1().Secrets(ns).Delete(ctx, csr.Annotations[experimentalapi.CertificateSigningRequestPrivateKeyAnnotationKey], metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create requester's private key Secret")
}

func createSelfSignedIssuer(ctx context.Context, f *framework.Framework) string {
	By("Creating a SelfSigned Issuer")

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-issuer-",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				SelfSigned: &cmapi.SelfSignedIssuer{},
			},
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

	// wait for issuer to be ready
	By("Waiting for Self Signed Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("issuers.cert-manager.io/%s.%s", f.Namespace.Name, issuer.Name)
}

func createSelfSignedClusterIssuer(ctx context.Context, f *framework.Framework) string {
	By("Creating a SelfSigned ClusterIssuer")

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-cluster-issuer-",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				SelfSigned: &cmapi.SelfSignedIssuer{},
			},
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

	// wait for issuer to be ready
	By("Waiting for Self Signed Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}

func deleteSelfSignedClusterIssuer(ctx context.Context, f *framework.Framework, signerName string) {
	ref, _ := util.SignerIssuerRefFromSignerName(signerName)
	err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, ref.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}
