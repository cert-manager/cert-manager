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

package step

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	stepaddon "github.com/jetstack/cert-manager/test/e2e/framework/addon/step"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

var _ = framework.CertManagerDescribe("Step Issuer", func() {
	f := framework.NewDefaultFramework("create-step-issuer")

	var (
		tiller = &tiller.Tiller{
			Name:               "tiller-deploy",
			ClusterPermissions: false,
		}
		step = &stepaddon.Step{
			Tiller: tiller,
			Name:   "cm-e2e-create-step-issuer",
		}
	)

	BeforeEach(func() {
		tiller.Namespace = f.Namespace.Name
		step.Namespace = f.Namespace.Name
	})

	f.RequireAddon(tiller)
	f.RequireAddon(step)

	issuerName := "test-step-issuer"

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
	})

	It("should be ready with the valid configuration", func() {
		s := step.Details()
		By("Creating an Issuer")
		stepIssuer := util.NewCertManagerStepIssuer(issuerName, s.Host, s.ProvisionerName, s.ProvisionerKeyID, s.ProvisionerPasswordRef, s.ProvisionerPasswordKey, s.CABundle)
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(stepIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			stepIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be ready with the valid kid but invalid name", func() {
		s := step.Details()
		By("Creating an Issuer")
		stepIssuer := util.NewCertManagerStepIssuer(issuerName, s.Host, "foo", s.ProvisionerKeyID, s.ProvisionerPasswordRef, s.ProvisionerPasswordKey, s.CABundle)
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(stepIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			stepIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail with an invalid provisioner kid", func() {
		s := step.Details()
		By("Creating an Issuer")
		stepIssuer := util.NewCertManagerStepIssuer(issuerName, s.Host, s.ProvisionerName, "foo", s.ProvisionerPasswordRef, s.ProvisionerPasswordKey, s.CABundle)
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(stepIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			stepIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail with the system ca bundle", func() {
		s := step.Details()
		By("Creating an Issuer")
		stepIssuer := util.NewCertManagerStepIssuer(issuerName, s.Host, s.ProvisionerName, s.ProvisionerKeyID, s.ProvisionerPasswordRef, s.ProvisionerPasswordKey, nil)
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(stepIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			stepIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail with an invalid ca bundle", func() {
		s := step.Details()
		By("Creating a random CA bundle")
		randomBundle, _, err := generateCA()
		Expect(err).NotTo(HaveOccurred())

		By("Creating an Issuer")
		stepIssuer := util.NewCertManagerStepIssuer(issuerName, s.Host, s.ProvisionerName, s.ProvisionerKeyID, s.ProvisionerPasswordRef, s.ProvisionerPasswordKey, randomBundle)
		_, err = f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(stepIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			stepIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})

func generateCA() ([]byte, []byte, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization: []string{"cert-manager test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := &privateKey.PublicKey
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create ca failed: %v", err)
	}

	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create ca failed: %v", err)
	}

	return encodePublicKey(caBytes), encodePrivateKey(privBytes), nil
}

func encodePublicKey(pub []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pub})
}

func encodePrivateKey(priv []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv})
}
