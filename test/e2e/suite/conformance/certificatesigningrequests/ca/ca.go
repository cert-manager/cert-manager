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

package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificatesigningrequests"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.ConformanceDescribe("CertificateSigningRequests", func() {
	caIssuer := new(ca)
	(&certificatesigningrequests.Suite{
		Name:             "CA Issuer",
		CreateIssuerFunc: caIssuer.createIssuer,
	}).Define()

	caClusterIssuer := new(ca)
	(&certificatesigningrequests.Suite{
		Name:             "CA ClusterIssuer",
		CreateIssuerFunc: caClusterIssuer.createClusterIssuer,
		DeleteIssuerFunc: caClusterIssuer.deleteClusterIssuer,
	}).Define()
})

type ca struct {
	secretName string
}

func (c *ca) createIssuer(ctx context.Context, f *framework.Framework) string {
	By("Creating a CA Issuer")

	rootCertSecret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, newSigningKeypairSecret("root-ca-cert-"), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create root signing keypair secret")

	c.secretName = rootCertSecret.Name

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "ca-issuer-",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				CA: &cmapi.CAIssuer{
					SecretName: rootCertSecret.Name,
				},
			},
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create ca issuer")

	// wait for issuer to be ready
	By("Waiting for CA Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("issuers.cert-manager.io/%s.%s", f.Namespace.Name, issuer.Name)
}

func (c *ca) createClusterIssuer(ctx context.Context, f *framework.Framework) string {
	By("Creating a CA ClusterIssuer")

	rootCertSecret, err := f.KubeClientSet.CoreV1().Secrets(f.Config.Addons.CertManager.ClusterResourceNamespace).Create(ctx, newSigningKeypairSecret("root-ca-cert-"), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create root signing keypair secret")

	c.secretName = rootCertSecret.Name

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "ca-cluster-issuer-",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				CA: &cmapi.CAIssuer{
					SecretName: rootCertSecret.Name,
				},
			},
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create ca issuer")

	// wait for issuer to be ready
	By("Waiting for CA Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}

func (c *ca) deleteClusterIssuer(ctx context.Context, f *framework.Framework, signerName string) {
	By("Deleting CA ClusterIssuer")
	ref, _ := util.SignerIssuerRefFromSignerName(signerName)

	err := f.KubeClientSet.CoreV1().Secrets(f.Config.Addons.CertManager.ClusterResourceNamespace).Delete(ctx, c.secretName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to delete root signing keypair secret")

	err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, ref.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to delete ca issuer")
}

func newSigningKeypairSecret(name string) *corev1.Secret {
	key, err := pki.GenerateRSAPrivateKey(2048)
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "cert-manager-e2e-test-ca",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		PublicKey: key.Public(),
		IsCA:      true,
	}

	pem, _, err := pki.SignCertificate(tmpl, tmpl, key.Public(), key)
	Expect(err).NotTo(HaveOccurred())

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: name,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       pem,
			corev1.TLSPrivateKeyKey: pki.EncodePKCS1PrivateKey(key),
		},
	}
}
