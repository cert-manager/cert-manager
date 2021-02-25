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

package vault

import (
	"context"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/util"
	vaultinternal "github.com/cert-manager/cert-manager/pkg/internal/vault"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	CRControllerName = "certificaterequests-issuer-vault"
)

type Vault struct {
	issuerOptions controllerpkg.IssuerOptions
	secretsLister corelisters.SecretLister
	reporter      *crutil.Reporter

	vaultClientBuilder vaultinternal.VaultClientBuilder
}

func init() {
	// create certificate request controller for vault issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CRControllerName).
			For(certificaterequests.New(apiutil.IssuerVault, NewVault(ctx))).
			Complete()
	})
}

func NewVault(ctx *controllerpkg.Context) *Vault {
	return &Vault{
		issuerOptions:      ctx.IssuerOptions,
		secretsLister:      ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		reporter:           crutil.NewReporter(ctx.Clock, ctx.Recorder),
		vaultClientBuilder: vaultinternal.New,
	}
}

func (v *Vault) Sign(ctx context.Context, cr *v1.CertificateRequest, issuerObj v1.GenericIssuer) (*issuer.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")
	log = logf.WithRelatedResource(log, issuerObj)

	resourceNamespace := v.issuerOptions.ResourceNamespace(issuerObj)

	client, err := v.vaultClientBuilder(resourceNamespace, v.secretsLister, issuerObj)
	if k8sErrors.IsNotFound(err) {
		message := "Required secret resource not found"

		v.reporter.Pending(cr, err, "SecretMissing", message)
		log.Error(err, message)
		return nil, nil
	}

	// TODO: distinguish between network errors and other which might warrant a failure.
	if err != nil {
		message := "Failed to initialise vault client for signing"
		v.reporter.Pending(cr, err, "VaultInitError", message)
		log.Error(err, message)
		return nil, nil
	}

	certDuration := apiutil.DefaultCertDuration(cr.Spec.Duration)
	certPem, caPem, err := client.Sign(cr.Spec.Request, certDuration)
	if err != nil {
		message := "Vault failed to sign certificate"

		v.reporter.Failed(cr, err, "SigningError", message)
		log.Error(err, message)

		return nil, nil
	}

	log.V(logf.DebugLevel).Info("certificate issued")

	return &issuer.IssueResponse{
		Certificate: certPem,
		CA:          caPem,
	}, nil
}
