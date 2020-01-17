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

package venafi

import (
	"context"

	"github.com/Venafi/vcert/pkg/endpoint"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/jetstack/cert-manager/pkg/controller/certificaterequests/util"
	venafiinternal "github.com/jetstack/cert-manager/pkg/internal/venafi"
	issuerpkg "github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	CRControllerName = "certificaterequests-issuer-venafi"
)

type Venafi struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister corelisters.SecretLister
	reporter      *crutil.Reporter

	clientBuilder venafiinternal.VenafiClientBuilder
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
		clientBuilder: venafiinternal.New,
	}
}

func (v *Venafi) Sign(ctx context.Context, cr *cmapi.CertificateRequest, issuerObj cmapi.GenericIssuer) (*issuerpkg.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")
	log = logf.WithRelatedResource(log, issuerObj)

	client, err := v.clientBuilder(cr.Namespace, v.secretsLister, issuerObj)
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

	duration := apiutil.DefaultCertDuration(cr.Spec.Duration)

	certPem, err := client.Sign(cr.Spec.CSRPEM, duration)

	// Check some known error types
	if err != nil {
		switch err.(type) {

		case endpoint.ErrCertificatePending:
			message := "Venafi certificate still in a pending state, the request will be retried"

			v.reporter.Pending(cr, err, "IssuancePending", message)
			log.Error(err, message)
			return nil, err

		case endpoint.ErrRetrieveCertificateTimeout:
			message := "Timed out waiting for venafi certificate, the request will be retried"

			v.reporter.Failed(cr, err, "Timeout", message)
			log.Error(err, message)
			return nil, nil

		default:
			message := "Failed to obtain venafi certificate"

			v.reporter.Failed(cr, err, "RetrieveError", message)
			log.Error(err, message)

			return nil, err
		}
	}

	log.Info("certificate issued")

	return &issuerpkg.IssueResponse{
		Certificate: certPem,
	}, nil
}
