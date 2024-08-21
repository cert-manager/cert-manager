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
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cert-manager/cert-manager/pkg/util/kube"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	// CSRControllerName holds the controller name
	CSRControllerName = "certificatesigningrequests-issuer-selfsigned"
)

type signingFn func(*x509.Certificate, *x509.Certificate, crypto.PublicKey, interface{}) ([]byte, *x509.Certificate, error)

// SelfSigned is a controller for signing Kubernetes CertificateSigningRequest
// using SelfSigning Issuers.
type SelfSigned struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister internalinformers.SecretLister

	certClient certificatesclient.CertificateSigningRequestInterface

	// fieldManager is the manager name used for the Apply operations.
	fieldManager string

	recorder record.EventRecorder

	// Used for testing to get reproducible resulting certificates
	signingFn signingFn
}

func init() {
	// create certificate signing request controller for selfsigned issuer
	controllerpkg.Register(CSRControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CSRControllerName).
			For(certificatesigningrequests.New(
				apiutil.IssuerSelfSigned, NewSelfSigned,

				// Handle informed Secrets which may be referenced by the
				// "experimental.cert-manager.io/private-key-secret-name" annotation.
				func(ctx *controllerpkg.Context, log logr.Logger, queue workqueue.TypedRateLimitingInterface[types.NamespacedName]) ([]cache.InformerSynced, error) {
					secretInformer := ctx.KubeSharedInformerFactory.Secrets().Informer()
					certificateSigningRequestLister := ctx.KubeSharedInformerFactory.CertificateSigningRequests().Lister()
					helper := issuer.NewHelper(
						ctx.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
						ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers().Lister(),
					)
					if _, err := secretInformer.AddEventHandler(&controllerpkg.BlockingEventHandler{
						WorkFunc: handleSecretReferenceWorkFunc(log, certificateSigningRequestLister, helper, queue, ctx.IssuerOptions),
					}); err != nil {
						return nil, fmt.Errorf("error setting up event handler: %v", err)
					}
					return []cache.InformerSynced{
						secretInformer.HasSynced,
						ctx.SharedInformerFactory.Certmanager().V1().Issuers().Informer().HasSynced,
						ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers().Informer().HasSynced,
					}, nil
				},
			)).
			Complete()
	})
}

// NewSelfSigned returns a new instance of SelfSigned type
func NewSelfSigned(ctx *controllerpkg.Context) certificatesigningrequests.Signer {
	return &SelfSigned{
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Secrets().Lister(),
		certClient:    ctx.Client.CertificatesV1().CertificateSigningRequests(),
		fieldManager:  ctx.FieldManager,
		recorder:      ctx.Recorder,
		signingFn:     pki.SignCertificate,
	}
}

// Sign attempts to sign the given CertificateSigningRequest based on the
// provided SelfSigned Issuer or ClusterIssuer. This function will update the
// resource if signing was successful. Returns an error which, if not nil,
// should trigger a retry.
// CertificateSigningRequests must have the
// "experimental.cert-manager.io/private-key-secret-name" annotation present to
// be signed. This annotation must reference a valid Secret containing a
// private key for signing.
func (s *SelfSigned) Sign(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, issuerObj cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx, "sign")

	secretName, ok := csr.GetAnnotations()[experimentalapi.CertificateSigningRequestPrivateKeyAnnotationKey]
	if !ok || len(secretName) == 0 {
		message := fmt.Sprintf("Missing private key reference annotation: %q", experimentalapi.CertificateSigningRequestPrivateKeyAnnotationKey)
		log.Error(errors.New(message), "")
		s.recorder.Event(csr, corev1.EventTypeWarning, "MissingAnnotation", message)
		util.CertificateSigningRequestSetFailed(csr, "MissingAnnotation", message)
		_, err := util.UpdateOrApplyStatus(ctx, s.certClient, csr, certificatesv1.CertificateFailed, s.fieldManager)
		return err
	}

	resourceNamespace := s.issuerOptions.ResourceNamespace(issuerObj)

	privatekey, err := kube.SecretTLSKey(ctx, s.secretsLister, resourceNamespace, secretName)
	if apierrors.IsNotFound(err) {
		message := fmt.Sprintf("Referenced Secret %s/%s not found", resourceNamespace, secretName)
		log.Error(err, message)
		s.recorder.Event(csr, corev1.EventTypeWarning, "SecretNotFound", message)
		return nil
	}

	if cmerrors.IsInvalidData(err) {
		message := fmt.Sprintf("Failed to parse signing key from secret %s/%s", resourceNamespace, secretName)
		log.Error(err, message)
		s.recorder.Eventf(csr, corev1.EventTypeWarning, "ErrorParsingKey", "%s: %s", message, err)
		return nil
	}

	if err != nil {
		// We are probably in a network error here so we should backoff and retry
		message := fmt.Sprintf("Failed to get certificate CA key from secret %s/%s", resourceNamespace, secretName)
		log.Error(err, message)
		s.recorder.Eventf(csr, corev1.EventTypeWarning, "ErrorGettingSecret", "%s: %s", message, err)
		util.CertificateSigningRequestSetFailed(csr, "ErrorGettingSecret", message)
		_, err = util.UpdateOrApplyStatus(ctx, s.certClient, csr, certificatesv1.CertificateFailed, s.fieldManager)
		return err
	}

	template, err := pki.CertificateTemplateFromCertificateSigningRequest(csr)
	if err != nil {
		message := fmt.Sprintf("Error generating certificate template: %s", err)
		log.Error(err, message)
		s.recorder.Event(csr, corev1.EventTypeWarning, "ErrorGenerating", message)
		util.CertificateSigningRequestSetFailed(csr, "ErrorGenerating", message)
		_, err = util.UpdateOrApplyStatus(ctx, s.certClient, csr, certificatesv1.CertificateFailed, s.fieldManager)
		return err
	}

	template.CRLDistributionPoints = issuerObj.GetSpec().SelfSigned.CRLDistributionPoints

	// extract the public component of the key
	publickey, err := pki.PublicKeyForPrivateKey(privatekey)
	if err != nil {
		message := "Failed to get public key from private key"
		log.Error(err, message)
		s.recorder.Event(csr, corev1.EventTypeWarning, "ErrorPublicKey", message)
		util.CertificateSigningRequestSetFailed(csr, "ErrorPublicKey", message)
		_, err = util.UpdateOrApplyStatus(ctx, s.certClient, csr, certificatesv1.CertificateFailed, s.fieldManager)
		return err
	}

	ok, err = pki.PublicKeysEqual(publickey, template.PublicKey)
	if err != nil || !ok {
		if err == nil {
			err = errors.New("CSR not signed by referenced private key")
		}

		message := "Referenced private key in Secret does not match that in the request"
		log.Error(err, message)
		s.recorder.Event(csr, corev1.EventTypeWarning, "ErrorKeyMatch", message)
		util.CertificateSigningRequestSetFailed(csr, "ErrorKeyMatch", message)
		_, err = util.UpdateOrApplyStatus(ctx, s.certClient, csr, certificatesv1.CertificateFailed, s.fieldManager)
		return err
	}

	certPEM, _, err := s.signingFn(template, template, publickey, privatekey)
	if err != nil {
		message := fmt.Sprintf("Error signing certificate: %s", err)
		s.recorder.Event(csr, corev1.EventTypeWarning, "ErrorSigning", message)
		util.CertificateSigningRequestSetFailed(csr, "ErrorSigning", message)
		_, err = util.UpdateOrApplyStatus(ctx, s.certClient, csr, certificatesv1.CertificateFailed, s.fieldManager)
		return err
	}

	csr.Status.Certificate = certPEM
	csr, err = util.UpdateOrApplyStatus(ctx, s.certClient, csr, "", s.fieldManager)
	if err != nil {
		message := "Error updating certificate"
		s.recorder.Eventf(csr, corev1.EventTypeWarning, "ErrorUpdate", "%s: %s", message, err)
		return err
	}

	log.V(logf.DebugLevel).Info("self signed certificate issued")
	s.recorder.Event(csr, corev1.EventTypeNormal, "CertificateIssued", "Certificate self signed successfully")

	return nil
}
