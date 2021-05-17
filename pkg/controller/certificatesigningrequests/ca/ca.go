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
	"encoding/base64"
	"fmt"

	certificatesv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	cmerrors "github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	CSRControllerName = "certificatesigningrequests-issuer-ca"
)

type templateGenerator func(*certificatesv1.CertificateSigningRequest) (*x509.Certificate, error)

type CA struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister corelisters.SecretLister

	certClient certificatesclient.CertificateSigningRequestInterface

	//reporter *crutil.Reporter

	// Used for testing to get reproducible resulting certificates
	templateGenerator templateGenerator
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
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		certClient:    ctx.Client.CertificatesV1().CertificateSigningRequests(),
		//reporter:          crutil.NewReporter(ctx.Clock, ctx.Recorder),
		templateGenerator: pki.GenerateTemplateFromCertificateSigningRequest,
	}
}

// Returns a nil certificate and no error when the error is not retryable,
// i.e., re-running the Sign command will lead to the same result. A
// retryable error would be for example a network failure.
func (c *CA) Sign(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, issuerObj cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx, "sign")

	secretName := issuerObj.GetSpec().CA.SecretName
	resourceNamespace := c.issuerOptions.ResourceNamespace(issuerObj)

	// get a copy of the CA certificate named on the Issuer
	caCerts, caKey, err := kube.SecretTLSKeyPair(ctx, c.secretsLister, resourceNamespace, issuerObj.GetSpec().CA.SecretName)
	if apierrors.IsNotFound(err) {
		message := fmt.Sprintf("Referenced secret %s/%s not found", resourceNamespace, secretName)

		//c.reporter.Pending(cr, err, "SecretMissing", message)
		log.Error(err, message)

		return nil
	}

	if cmerrors.IsInvalidData(err) {
		message := fmt.Sprintf("Failed to parse signing CA keypair from secret %s/%s", resourceNamespace, secretName)

		//c.reporter.Pending(cr, err, "SecretInvalidData", message)
		log.Error(err, message)
		return nil
	}

	if err != nil {
		// We are probably in a network error here so we should backoff and retry
		message := fmt.Sprintf("Failed to get certificate key pair from secret %s/%s", resourceNamespace, secretName)
		//c.reporter.Pending(cr, err, "SecretGetError", message)
		log.Error(err, message)
		return err
	}

	template, err := c.templateGenerator(csr)
	if err != nil {
		message := "Error generating certificate template"
		//c.reporter.Failed(csr, err, "SigningError", message)
		log.Error(err, message)
		return nil
	}

	template.CRLDistributionPoints = issuerObj.GetSpec().CA.CRLDistributionPoints
	template.OCSPServer = issuerObj.GetSpec().CA.OCSPServers

	bundle, err := pki.SignCSRTemplate(caCerts, caKey, template)
	if err != nil {
		message := "Error signing certificate"
		//c.reporter.Failed(cr, err, "SigningError", message)
		log.Error(err, message)
		return nil
	}

	csr.Status.Certificate = bundle.ChainPEM
	csr, err = c.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
	if err != nil {
		// TODO
		message := "Error updating certificate"
		log.Error(err, message)
		return err
	}

	csr.Annotations[cmapi.CertificateSigningRequestCAAnnotationKey] = base64.StdEncoding.EncodeToString(bundle.CAPEM)
	_, err = c.certClient.Update(ctx, csr, metav1.UpdateOptions{})
	if err != nil {
		// TODO
		message := fmt.Sprintf("Error updating %q", cmapi.CertificateSigningRequestCAAnnotationKey)
		log.Error(err, message)
		return err
	}

	log.V(logf.DebugLevel).Info("certificate issued")

	return nil
}
