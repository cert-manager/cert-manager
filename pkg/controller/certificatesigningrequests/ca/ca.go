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
	"crypto"
	"crypto/x509"
	"fmt"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests"
	"github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests/util"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	cmerrors "github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	CSRControllerName = "certificatesigningrequests-issuer-ca"
)

type templateGenerator func(*certificatesv1.CertificateSigningRequest) (*x509.Certificate, error)
type signingFn func([]*x509.Certificate, crypto.Signer, *x509.Certificate) (pki.PEMBundle, error)

// CA is a Kubernetes CertificateSigningRequest controller, responsible for
// signing CertificateSigningRequests that reference a cert-manager CA Issuer
// or ClusterIssuer
type CA struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister corelisters.SecretLister

	certClient certificatesclient.CertificateSigningRequestInterface

	recorder record.EventRecorder

	// Used for testing to get reproducible resulting certificates
	templateGenerator templateGenerator
	signingFn         signingFn
}

func init() {
	// create certificate request controller for ca issuer
	controllerpkg.Register(CSRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CSRControllerName).
			For(certificatesigningrequests.New(apiutil.IssuerCA, NewCA(ctx))).
			Complete()
	})
}

func NewCA(ctx *controllerpkg.Context) *CA {
	return &CA{
		issuerOptions:     ctx.IssuerOptions,
		secretsLister:     ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		certClient:        ctx.Client.CertificatesV1().CertificateSigningRequests(),
		recorder:          ctx.Recorder,
		templateGenerator: pki.GenerateTemplateFromCertificateSigningRequest,
		signingFn:         pki.SignCSRTemplate,
	}
}

// Sign attempts to sign the given CertificateSigningRequest based on the
// provided CA Issuer or ClusterIssuer. This function will update the resource
// if signing was successful. Returns an error which, if not nil, should
// trigger a retry.
func (c *CA) Sign(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, issuerObj cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx, "sign")

	secretName := issuerObj.GetSpec().CA.SecretName
	resourceNamespace := c.issuerOptions.ResourceNamespace(issuerObj)

	// get a copy of the CA certificate named on the Issuer
	caCerts, caKey, err := kube.SecretTLSKeyPairAndCA(ctx, c.secretsLister, resourceNamespace, issuerObj.GetSpec().CA.SecretName)
	if apierrors.IsNotFound(err) {
		message := fmt.Sprintf("Referenced secret %s/%s not found", resourceNamespace, secretName)
		c.recorder.Event(csr, corev1.EventTypeWarning, "SecretMissing", message)
		return nil
	}

	if cmerrors.IsInvalidData(err) {
		message := fmt.Sprintf("Failed to parse signing CA keypair from secret %s/%s", resourceNamespace, secretName)
		c.recorder.Eventf(csr, corev1.EventTypeWarning, "SecretInvalidData", "%s: %s", message, err)
		return nil
	}

	if err != nil {
		// We are probably in a network error here so we should backoff and retry
		message := fmt.Sprintf("Failed to get certificate key pair from secret %s/%s", resourceNamespace, secretName)
		c.recorder.Eventf(csr, corev1.EventTypeWarning, "SecretGetError", "%s: %s", message, err)
		return err
	}

	template, err := c.templateGenerator(csr)
	if err != nil {
		message := fmt.Sprintf("Error generating certificate template: %s", err)
		c.recorder.Event(csr, corev1.EventTypeWarning, "SigningError", message)
		util.CertificateSigningRequestSetFailed(csr, "SigningError", message)
		_, err = c.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
		return err
	}

	template.CRLDistributionPoints = issuerObj.GetSpec().CA.CRLDistributionPoints
	template.OCSPServer = issuerObj.GetSpec().CA.OCSPServers

	bundle, err := c.signingFn(caCerts, caKey, template)
	if err != nil {
		message := fmt.Sprintf("Error signing certificate: %s", err)
		c.recorder.Event(csr, corev1.EventTypeWarning, "SigningError", message)
		util.CertificateSigningRequestSetFailed(csr, "SigningError", message)
		_, err := c.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
		return err
	}

	csr.Status.Certificate = bundle.ChainPEM
	csr, err = c.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
	if err != nil {
		message := "Error updating certificate"
		c.recorder.Eventf(csr, corev1.EventTypeWarning, "SigningError", "%s: %s", message, err)
		return err
	}

	log.V(logf.DebugLevel).Info("certificate issued")
	c.recorder.Event(csr, corev1.EventTypeNormal, "CertificateIssued", "Certificate fetched from issuer successfully")

	return nil
}
