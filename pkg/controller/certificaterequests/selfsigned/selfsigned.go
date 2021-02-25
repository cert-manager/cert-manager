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
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/util"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cert-manager/cert-manager/pkg/util/kube"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	CRControllerName = "certificaterequests-issuer-selfsigned"
)

type signingFn func(*x509.Certificate, *x509.Certificate, crypto.PublicKey, interface{}) ([]byte, *x509.Certificate, error)

type SelfSigned struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister corelisters.SecretLister

	reporter *crutil.Reporter

	// Used for testing to get reproducible resulting certificates
	signingFn signingFn
}

func init() {
	// create certificate request controller for selfsigned issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CRControllerName).
			For(certificaterequests.New(apiutil.IssuerSelfSigned, NewSelfSigned(ctx))).
			Complete()
	})
}

func NewSelfSigned(ctx *controllerpkg.Context) *SelfSigned {
	return &SelfSigned{
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		reporter:      crutil.NewReporter(ctx.Clock, ctx.Recorder),
		signingFn:     pki.SignCertificate,
	}
}

func (s *SelfSigned) Sign(ctx context.Context, cr *cmapi.CertificateRequest, issuerObj cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")

	resourceNamespace := s.issuerOptions.ResourceNamespace(issuerObj)

	secretName, ok := cr.ObjectMeta.Annotations[cmapi.CertificateRequestPrivateKeyAnnotationKey]
	if !ok || secretName == "" {
		message := fmt.Sprintf("Annotation %q missing or reference empty",
			cmapi.CertificateRequestPrivateKeyAnnotationKey)
		err := errors.New("secret name missing")

		s.reporter.Failed(cr, err, "MissingAnnotation", message)
		log.Error(err, message)

		return nil, nil
	}

	privatekey, err := kube.SecretTLSKey(ctx, s.secretsLister, cr.Namespace, secretName)
	if k8sErrors.IsNotFound(err) {
		message := fmt.Sprintf("Referenced secret %s/%s not found", cr.Namespace, secretName)

		s.reporter.Pending(cr, err, "MissingSecret", message)
		log.Error(err, message)

		return nil, nil
	}

	if cmerrors.IsInvalidData(err) {
		message := fmt.Sprintf("Failed to get key %q referenced in annotation %q",
			secretName, cmapi.CertificateRequestPrivateKeyAnnotationKey)

		s.reporter.Pending(cr, err, "ErrorParsingKey", message)
		log.Error(err, message)

		return nil, nil
	}

	if err != nil {
		// We are probably in a network error here so we should backoff and retry
		message := fmt.Sprintf("Failed to get certificate key pair from secret %s/%s", resourceNamespace, secretName)
		s.reporter.Pending(cr, err, "ErrorGettingSecret", message)
		log.Error(err, message)
		return nil, err
	}

	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		message := "Error generating certificate template"
		s.reporter.Failed(cr, err, "ErrorGenerating", message)
		log.Error(err, message)
		return nil, nil
	}

	template.CRLDistributionPoints = issuerObj.GetSpec().SelfSigned.CRLDistributionPoints

	// extract the public component of the key
	publickey, err := pki.PublicKeyForPrivateKey(privatekey)
	if err != nil {
		message := "Failed to get public key from private key"
		s.reporter.Failed(cr, err, "ErrorPublicKey", message)
		log.Error(err, message)
		return nil, nil
	}

	ok, err = pki.PublicKeysEqual(publickey, template.PublicKey)
	if err != nil || !ok {

		if err == nil {
			err = errors.New("CSR not signed by referenced private key")
		}

		message := "Error generating certificate template"
		s.reporter.Failed(cr, err, "ErrorKeyMatch", message)
		log.Error(err, message)

		return nil, nil
	}

	// sign and encode the certificate
	certPem, _, err := s.signingFn(template, template, publickey, privatekey)
	if err != nil {
		message := "Error signing certificate"
		s.reporter.Failed(cr, err, "ErrorSigning", message)
		log.Error(err, message)
		return nil, nil
	}

	log.V(logf.DebugLevel).Info("self signed certificate issued")

	// We set the CA to the returned certificate here since this is self signed.
	return &issuer.IssueResponse{
		Certificate: certPem,
		CA:          certPem,
	}, nil
}
