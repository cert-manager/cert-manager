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

package venafi

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	"k8s.io/client-go/tools/record"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	venaficlient "github.com/cert-manager/cert-manager/pkg/issuer/venafi/client"
	venafiapi "github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/api"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	CSRControllerName = "certificatesigningrequests-issuer-venafi"
)

// Venafi is a Kubernetes CertificateSigningRequest controller, responsible for
// signing CertificateSigningRequests that reference a cert-manager Venafi
// Issuer or ClusterIssuer
type Venafi struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister internalinformers.SecretLister
	certClient    certificatesclient.CertificateSigningRequestInterface
	recorder      record.EventRecorder

	clientBuilder venaficlient.VenafiClientBuilder

	metrics *metrics.Metrics

	// fieldManager is the manager name used for the Apply operations.
	fieldManager string

	// userAgent is the string used as the UserAgent when making HTTP calls.
	userAgent string
}

func init() {
	controllerpkg.Register(CSRControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CSRControllerName).
			For(certificatesigningrequests.New(apiutil.IssuerVenafi, NewVenafi)).
			Complete()
	})
}

func NewVenafi(ctx *controllerpkg.Context) certificatesigningrequests.Signer {
	return &Venafi{
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Secrets().Lister(),
		certClient:    ctx.Client.CertificatesV1().CertificateSigningRequests(),
		recorder:      ctx.Recorder,
		clientBuilder: venaficlient.New,
		fieldManager:  ctx.FieldManager,
		metrics:       ctx.Metrics,
		userAgent:     ctx.RESTConfig.UserAgent,
	}
}

// Sign attempts to sign the given CertificateSigningRequest based on the
// provided Venafi Issuer or ClusterIssuer. This function will update the resource
// if signing was successful. Returns an error which, if not nil, should
// trigger a retry.
// Since this signer takes some time to sign the request, this controller will
// set a "pick ID" annotation value that is used to fetch the latest state of
// the request in subsequent re-syncs. The re-syncs are triggered by using the
// workqueue's back-off mechanism.
func (v *Venafi) Sign(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, issuerObj cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx, "sign")
	log = logf.WithRelatedResource(log, issuerObj)

	resourceNamespace := v.issuerOptions.ResourceNamespace(issuerObj)

	client, err := v.clientBuilder(resourceNamespace, v.secretsLister, issuerObj, v.metrics, log, v.userAgent)
	if apierrors.IsNotFound(err) {
		message := "Required secret resource not found"
		v.recorder.Event(csr, corev1.EventTypeWarning, "SecretNotFound", message)
		log.Error(err, message)
		return nil
	}

	if err != nil {
		message := fmt.Sprintf("Failed to initialise venafi client for signing: %s", err)
		v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorVenafiInit", message)
		log.Error(err, message)
		return err
	}

	var customFields []venafiapi.CustomField
	if annotation, exists := csr.GetAnnotations()[experimentalapi.CertificateSigningRequestVenafiCustomFieldsAnnotationKey]; exists && annotation != "" {
		err := json.Unmarshal([]byte(annotation), &customFields)
		if err != nil {
			message := fmt.Sprintf("Failed to parse %q annotation: %s", experimentalapi.CertificateSigningRequestVenafiCustomFieldsAnnotationKey, err)
			v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorCustomFields", message)
			util.CertificateSigningRequestSetFailed(csr, "ErrorCustomFields", message)
			_, userr := util.UpdateOrApplyStatus(ctx, v.certClient, csr, certificatesv1.CertificateFailed, v.fieldManager)
			return userr
		}
	}

	duration, err := pki.DurationFromCertificateSigningRequest(csr)
	if err != nil {
		message := fmt.Sprintf("Failed to parse requested duration: %s", err)
		log.Error(err, message)
		v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorParseDuration", message)
		util.CertificateSigningRequestSetFailed(csr, "ErrorParseDuration", message)
		_, userr := util.UpdateOrApplyStatus(ctx, v.certClient, csr, certificatesv1.CertificateFailed, v.fieldManager)
		return userr
	}

	// The signing process with Venafi is slow. The "pickupID" allows us to track
	// the progress of the certificate signing. It is set as an annotation the
	// first time the Certificate is reconciled.
	pickupID := csr.GetAnnotations()[experimentalapi.CertificateSigningRequestVenafiPickupIDAnnotationKey]

	// check if the pickup ID annotation is there, if not set it up.
	if len(pickupID) == 0 {
		pickupID, err := client.RequestCertificate(csr.Spec.Request, duration, customFields)
		// Check some known error types
		if err != nil {
			switch err.(type) {

			case venaficlient.ErrCustomFieldsType:
				log.Error(err, "")
				v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorCustomFields", err.Error())
				util.CertificateSigningRequestSetFailed(csr, "ErrorCustomFields", err.Error())
				_, userr := util.UpdateOrApplyStatus(ctx, v.certClient, csr, certificatesv1.CertificateFailed, v.fieldManager)
				return userr

			default:
				message := fmt.Sprintf("Failed to request venafi certificate: %s", err)
				log.Error(err, message)
				v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorRequest", message)
				util.CertificateSigningRequestSetFailed(csr, "ErrorRequest", message)
				_, userr := util.UpdateOrApplyStatus(ctx, v.certClient, csr, certificatesv1.CertificateFailed, v.fieldManager)
				return userr
			}
		}

		if csr.Annotations == nil {
			csr.Annotations = make(map[string]string)
		}
		csr.Annotations[experimentalapi.CertificateSigningRequestVenafiPickupIDAnnotationKey] = pickupID
		_, uerr := v.certClient.Update(ctx, csr, metav1.UpdateOptions{})
		return uerr
	}

	certPem, err := client.RetrieveCertificate(pickupID, csr.Spec.Request, duration, customFields)
	if err != nil {
		switch err.(type) {
		case endpoint.ErrCertificatePending:
			message := "Venafi certificate still in a pending state, waiting"
			log.V(2).Info(message, "error", err.Error())
			v.recorder.Event(csr, corev1.EventTypeNormal, "IssuancePending", message)
			return err

		case endpoint.ErrRetrieveCertificateTimeout:
			message := "Venafi retrieve certificate timeout, retrying"
			log.Error(err, message)
			v.recorder.Event(csr, corev1.EventTypeWarning, "RetrieveCertificateTimeout", message)
			return err

		default:
			message := fmt.Sprintf("Failed to obtain venafi certificate: %s", err)
			log.Error(err, message)
			v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorRetrieve", message)
			return err
		}
	}

	bundle, err := utilpki.ParseSingleCertificateChainPEM(certPem)
	if err != nil {
		message := fmt.Sprintf("Failed to parse returned certificate bundle: %s", err)
		log.Error(err, message)
		v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorParse", message)
		util.CertificateSigningRequestSetFailed(csr, "ErrorParse", message)
		_, userr := util.UpdateOrApplyStatus(ctx, v.certClient, csr, certificatesv1.CertificateFailed, v.fieldManager)
		return userr
	}

	csr.Status.Certificate = bundle.ChainPEM
	csr, err = util.UpdateOrApplyStatus(ctx, v.certClient, csr, "", v.fieldManager)
	if err != nil {
		message := "Error updating certificate"
		v.recorder.Eventf(csr, corev1.EventTypeWarning, "SigningError", "%s: %s", message, err)
		return err
	}

	log.V(logf.DebugLevel).Info("certificate issued")
	v.recorder.Event(csr, corev1.EventTypeNormal, "CertificateIssued", "Certificate fetched from venafi issuer successfully")

	return nil
}
