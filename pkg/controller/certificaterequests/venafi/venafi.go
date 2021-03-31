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
	"encoding/pem"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/Venafi/vcert/v4/pkg/endpoint"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/jetstack/cert-manager/pkg/controller/certificaterequests/util"
	issuerpkg "github.com/jetstack/cert-manager/pkg/issuer"
	venaficlient "github.com/jetstack/cert-manager/pkg/issuer/venafi/client"
	"github.com/jetstack/cert-manager/pkg/issuer/venafi/client/api"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	CRControllerName = "certificaterequests-issuer-venafi"
)

type Venafi struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister corelisters.SecretLister
	reporter      *crutil.Reporter
	cmClient      clientset.Interface

	clientBuilder venaficlient.VenafiClientBuilder
}

func init() {
	// create certificate request controller for venafi issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CRControllerName).
			For(certificaterequests.New(apiutil.IssuerVenafi, NewVenafi(ctx))).
			Complete()
	})
}

func NewVenafi(ctx *controllerpkg.Context) *Venafi {
	return &Venafi{
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		reporter:      crutil.NewReporter(ctx.Clock, ctx.Recorder),
		clientBuilder: venaficlient.New,
		cmClient:      ctx.CMClient,
	}
}

func (v *Venafi) Sign(ctx context.Context, cr *cmapi.CertificateRequest, issuerObj cmapi.GenericIssuer) (*issuerpkg.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")
	log = logf.WithRelatedResource(log, issuerObj)

	client, err := v.clientBuilder(v.issuerOptions.ResourceNamespace(issuerObj), v.secretsLister, issuerObj)
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

	duration := apiutil.DefaultCertDuration(cr.Spec.Duration)
	pickupID := cr.ObjectMeta.Annotations[cmapi.VenafiPickupIDAnnotationKey]

	// check if the pickup ID annotation is there, if not set it up.
	if pickupID == "" {
		pickupID, err = client.RequestCertificate(cr.Spec.Request, duration, customFields)
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

	certPem, err := client.RetrieveCertificate(pickupID, cr.Spec.Request, duration, customFields)
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

	// Assume the last certificate is the root CA
	var (
		block, lastBlock *pem.Block
		remainingBytes   = certPem
	)
	for {
		block, remainingBytes = pem.Decode(remainingBytes)
		if block == nil {
			break
		}
		lastBlock = block
	}
	return &issuerpkg.IssueResponse{
		Certificate: certPem,
		CA:          pem.EncodeToMemory(lastBlock),
	}, nil
}
