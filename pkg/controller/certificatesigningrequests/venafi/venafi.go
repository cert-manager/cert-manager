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

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/jetstack/cert-manager/pkg/apis/experimental/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests"
	"github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests/util"
	venaficlient "github.com/jetstack/cert-manager/pkg/issuer/venafi/client"
	venafiapi "github.com/jetstack/cert-manager/pkg/issuer/venafi/client/api"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	CSRControllerName = "certificatesigningrequests-issuer-venafi"
)

// Venafi is a Kubernetes CertificateSigningRequest controller, responsible for
// signing CertificateSigningRequests that reference a cert-manager Venafi
// Issuer or ClusterIssuer
type Venafi struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister corelisters.SecretLister
	certClient    certificatesclient.CertificateSigningRequestInterface
	recorder      record.EventRecorder

	clientBuilder venaficlient.VenafiClientBuilder
}

func init() {
	controllerpkg.Register(CSRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CSRControllerName).
			For(certificatesigningrequests.New(apiutil.IssuerVenafi, NewVenafi(ctx))).
			Complete()
	})
}

func NewVenafi(ctx *controllerpkg.Context) *Venafi {
	return &Venafi{
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		certClient:    ctx.Client.CertificatesV1().CertificateSigningRequests(),
		recorder:      ctx.Recorder,
		clientBuilder: venaficlient.New,
	}
}

// Sign attempts to sign the given CertificateSigningRequest based on the
// provided Venafi Issuer or ClusterIssuer. This function will update the resource
// if signing was successful. Returns an error which, if not nil, should
// trigger a retry.
// Since this signer takes some time to sign the request, this controller will
// set a "pick ID" annotation value that is used to fetch the latest state of
// the request in subsequent re-syncs.
func (v *Venafi) Sign(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, issuerObj cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx, "sign")
	log = logf.WithRelatedResource(log, issuerObj)

	resourceNamespace := v.issuerOptions.ResourceNamespace(issuerObj)

	client, err := v.clientBuilder(resourceNamespace, v.secretsLister, issuerObj)
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
			_, err = v.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
			return err
		}
	}

	duration, err := pki.DurationFromCertificateSigningRequest(csr)
	if err != nil {
		message := fmt.Sprintf("Failed to parse requested duration: %s", err)
		log.Error(err, message)
		v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorParseDuration", message)
		util.CertificateSigningRequestSetFailed(csr, "ErrorParseDuration", message)
		_, err := v.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
		return err
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
				_, err := v.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
				return err

			default:
				message := fmt.Sprintf("Failed to request venafi certificate: %s", err)
				log.Error(err, message)
				v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorRequest", message)
				util.CertificateSigningRequestSetFailed(csr, "ErrorRequest", message)
				_, err := v.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
				return err
			}
		}

		if csr.Annotations == nil {
			csr.Annotations = make(map[string]string)
		}
		csr.Annotations[experimentalapi.CertificateSigningRequestVenafiPickupIDAnnotationKey] = pickupID
		_, err = v.certClient.Update(ctx, csr, metav1.UpdateOptions{})
		return err
	}

	certPem, err := client.RetrieveCertificate(pickupID, csr.Spec.Request, duration, customFields)
	if err != nil {
		switch err.(type) {
		case endpoint.ErrCertificatePending, endpoint.ErrRetrieveCertificateTimeout:
			message := "Venafi certificate still in a pending state, the request will be retried"
			log.Error(err, message)
			v.recorder.Event(csr, corev1.EventTypeNormal, "IssuancePending", message)
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
		_, err := v.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
		return err
	}

	csr.Status.Certificate = bundle.ChainPEM
	csr, err = v.certClient.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
	if err != nil {
		message := "Error updating certificate"
		v.recorder.Eventf(csr, corev1.EventTypeWarning, "SigningError", "%s: %s", message, err)
		return err
	}

	log.V(logf.DebugLevel).Info("certificate issued")
	v.recorder.Event(csr, corev1.EventTypeNormal, "CertificateIssued", "Certificate fetched from venafi issuer successfully")

	return nil
}
