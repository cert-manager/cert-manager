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
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/util"
	issuerpkg "github.com/cert-manager/cert-manager/pkg/issuer"
	venaficlient "github.com/cert-manager/cert-manager/pkg/issuer/venafi/client"
	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/api"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	CRControllerName = "certificaterequests-issuer-venafi"
)

type Venafi struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister internalinformers.SecretLister
	reporter      *crutil.Reporter
	cmClient      clientset.Interface

	clientBuilder venaficlient.VenafiClientBuilder

	metrics *metrics.Metrics

	// userAgent is the string used as the UserAgent when making HTTP calls.
	userAgent string
}

func init() {
	// create certificate request controller for venafi issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CRControllerName).
			For(certificaterequests.New(apiutil.IssuerVenafi, NewVenafi)).
			Complete()
	})
}

func NewVenafi(ctx *controllerpkg.Context) certificaterequests.Issuer {
	return &Venafi{
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Secrets().Lister(),
		reporter:      crutil.NewReporter(ctx.Clock, ctx.Recorder),
		clientBuilder: venaficlient.New,
		metrics:       ctx.Metrics,
		cmClient:      ctx.CMClient,
		userAgent:     ctx.RESTConfig.UserAgent,
	}
}

func (v *Venafi) Sign(ctx context.Context, cr *cmapi.CertificateRequest, issuerObj cmapi.GenericIssuer) (*issuerpkg.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")
	log = logf.WithRelatedResource(log, issuerObj)

	client, err := v.clientBuilder(v.issuerOptions.ResourceNamespace(issuerObj), v.secretsLister, issuerObj, v.metrics, log, v.userAgent)
	if k8sErrors.IsNotFound(err) {
		message := "Required secret resource not found"

		v.reporter.Pending(cr, err, "SecretMissing", message)
		log.Error(err, message)

		return nil, nil
	}

	if err != nil {
		message := "Failed to initialise venafi client for signing"

		v.reporter.Pending(cr, err, "VenafiInitError", message)
		log.Error(err, message)

		return nil, err
	}

	var customFields []api.CustomField
	if annotation, exists := cr.GetAnnotations()[cmapi.VenafiCustomFieldsAnnotationKey]; exists && annotation != "" {
		err := json.Unmarshal([]byte(annotation), &customFields)
		if err != nil {
			message := fmt.Sprintf("Failed to parse %q annotation", cmapi.VenafiCustomFieldsAnnotationKey)

			v.reporter.Failed(cr, err, "CustomFieldsError", message)
			log.Error(err, message)

			return nil, nil
		}
	}

	pickupID := cr.ObjectMeta.Annotations[cmapi.VenafiPickupIDAnnotationKey]

	// check if the pickup ID annotation is there, if not set it up.
	if pickupID == "" {
		pickupID, err = client.RequestCertificate(cr.Spec.Request, customFields)
		// Check some known error types
		if err != nil {
			switch err.(type) {

			case venaficlient.ErrCustomFieldsType:
				v.reporter.Failed(cr, err, "CustomFieldsError", err.Error())
				log.Error(err, err.Error())

				return nil, nil

			default:
				message := "Failed to request venafi certificate"

				v.reporter.Failed(cr, err, "RequestError", message)
				log.Error(err, message)

				return nil, err
			}
		}

		v.reporter.Pending(cr, err, "IssuancePending", "Venafi certificate is requested")

		metav1.SetMetaDataAnnotation(&cr.ObjectMeta, cmapi.VenafiPickupIDAnnotationKey, pickupID)

		return nil, nil
	}

	certPem, err := client.RetrieveCertificate(pickupID, cr.Spec.Request, customFields)
	if err != nil {
		switch err.(type) {
		case endpoint.ErrCertificatePending, endpoint.ErrRetrieveCertificateTimeout:
			message := "Venafi certificate still in a pending state, the request will be retried"

			v.reporter.Pending(cr, err, "IssuancePending", message)
			log.Error(err, message)
			return nil, err

		default:
			message := "Failed to obtain venafi certificate"

			v.reporter.Failed(cr, err, "RetrieveError", message)
			log.Error(err, message)

			return nil, err
		}
	}

	log.V(logf.DebugLevel).Info("certificate issued")

	bundle, err := utilpki.ParseSingleCertificateChainPEM(certPem)
	if err != nil {
		message := "Failed to parse returned certificate bundle"
		v.reporter.Failed(cr, err, "ParseError", message)
		log.Error(err, message)
		return nil, err
	}

	return &issuerpkg.IssueResponse{
		Certificate: bundle.ChainPEM,
		CA:          bundle.CAPEM,
	}, nil
}
