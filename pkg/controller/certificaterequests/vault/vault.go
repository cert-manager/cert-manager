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

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	vaultinternal "github.com/cert-manager/cert-manager/internal/vault"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/util"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
)

const (
	// CRControllerName is the name of Vault certificate requests controller.
	CRControllerName = "certificaterequests-issuer-vault"
)

// Vault is a Vault-specific implementation of
// pkg/controller/certificaterequests.Issuer interface.
type Vault struct {
	issuerOptions controllerpkg.IssuerOptions
	createTokenFn func(ns string) vaultinternal.CreateToken
	secretsLister internalinformers.SecretLister
	reporter      *crutil.Reporter

	vaultClientBuilder vaultinternal.ClientBuilder
}

func init() {
	// create certificate request controller for vault issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CRControllerName).
			For(certificaterequests.New(apiutil.IssuerVault, NewVault)).
			Complete()
	})
}

// NewVault returns a new Vault instance with the given controller context.
func NewVault(ctx *controllerpkg.Context) certificaterequests.Issuer {
	return &Vault{
		issuerOptions: ctx.IssuerOptions,
		createTokenFn: func(ns string) vaultinternal.CreateToken {
			return ctx.Client.CoreV1().ServiceAccounts(ns).CreateToken
		},
		secretsLister:      ctx.KubeSharedInformerFactory.Secrets().Lister(),
		reporter:           crutil.NewReporter(ctx.Clock, ctx.Recorder),
		vaultClientBuilder: vaultinternal.New,
	}
}

// Sign will connect to Vault server associated with the provided issuer to sign
// the X.509 certificate from the Certificate Request.
func (v *Vault) Sign(ctx context.Context, cr *v1.CertificateRequest, issuerObj v1.GenericIssuer) (*issuer.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")
	log = logf.WithRelatedResource(log, issuerObj)

	resourceNamespace := v.issuerOptions.ResourceNamespace(issuerObj)

	client, err := v.vaultClientBuilder(ctx, resourceNamespace, v.createTokenFn, v.secretsLister, issuerObj)
	if k8sErrors.IsNotFound(err) {
		message := "Required secret resource not found"

		v.reporter.Pending(cr, err, "SecretMissing", message)
		log.Error(err, message)
		return nil, nil
	}

	if err != nil {
		message := "Failed to initialise vault client for signing"
		v.reporter.Pending(cr, err, "VaultInitError", message)
		log.Error(err, message)

		if cmerrors.IsInvalidData(err) {
			return nil, nil // Don't retry, wait for the issuer to be updated
		}

		return nil, err // Return error to requeue and retry
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
