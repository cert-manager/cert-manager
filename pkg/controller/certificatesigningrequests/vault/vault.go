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

package vault

import (
	"context"
	"fmt"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	"k8s.io/client-go/tools/record"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	internalvault "github.com/cert-manager/cert-manager/internal/vault"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	CSRControllerName = "certificatesigningrequests-issuer-vault"
)

// Vault is a controller for signing Kubernetes CertificateSigningRequest
// using Vault Issuers.
type Vault struct {
	issuerOptions controllerpkg.IssuerOptions
	kclient       kubernetes.Interface
	secretsLister internalinformers.SecretLister

	recorder record.EventRecorder

	certClient    certificatesclient.CertificateSigningRequestInterface
	clientBuilder internalvault.ClientBuilder

	// fieldManager is the manager name used for the Apply operations.
	fieldManager string
}

func init() {
	controllerpkg.Register(CSRControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CSRControllerName).
			For(certificatesigningrequests.New(apiutil.IssuerVault, NewVault)).
			Complete()
	})
}

func NewVault(ctx *controllerpkg.Context) certificatesigningrequests.Signer {
	return &Vault{
		issuerOptions: ctx.IssuerOptions,
		kclient:       ctx.Client,
		secretsLister: ctx.KubeSharedInformerFactory.Secrets().Lister(),
		recorder:      ctx.Recorder,
		certClient:    ctx.Client.CertificatesV1().CertificateSigningRequests(),
		clientBuilder: internalvault.New,
		fieldManager:  ctx.FieldManager,
	}
}

// Sign attempts to sign the given CertificateSigningRequest based on the
// provided Vault Issuer or ClusterIssuer. This function updates the
// CertificateSigningRequest resource if signing was successful. Returns an
// error which, if not nil, should trigger a retry.
func (v *Vault) Sign(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, issuerObj cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx, "sign")
	log = logf.WithRelatedResource(log, issuerObj)

	resourceNamespace := v.issuerOptions.ResourceNamespace(issuerObj)

	createTokenFn := func(ns string) internalvault.CreateToken { return v.kclient.CoreV1().ServiceAccounts(ns).CreateToken }
	client, err := v.clientBuilder(ctx, resourceNamespace, createTokenFn, v.secretsLister, issuerObj)
	if apierrors.IsNotFound(err) {
		message := "Required secret resource not found"
		log.Error(err, message)
		v.recorder.Event(csr, corev1.EventTypeWarning, "SecretNotFound", message)
		util.CertificateSigningRequestSetFailed(csr, "SecretNotFound", message)
		_, err := util.UpdateOrApplyStatus(ctx, v.certClient, csr, certificatesv1.CertificateFailed, v.fieldManager)
		return err
	}

	if err != nil {
		message := fmt.Sprintf("Failed to initialise vault client for signing: %s", err)
		log.Error(err, message)
		v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorVaultInit", message)
		return err
	}

	duration, err := pki.DurationFromCertificateSigningRequest(csr)
	// We should never get to this point as the caller would have already
	// caught this condition
	if err != nil {
		message := fmt.Sprintf("Failed to parse requested duration: %s", err)
		log.Error(err, message)
		return nil
	}

	certPEM, _, err := client.Sign(csr.Spec.Request, duration)
	if err != nil {
		message := fmt.Sprintf("Vault failed to sign: %s", err)
		log.Error(err, message)
		v.recorder.Event(csr, corev1.EventTypeWarning, "ErrorSigning", message)
		util.CertificateSigningRequestSetFailed(csr, "ErrorSigning", message)
		_, err := util.UpdateOrApplyStatus(ctx, v.certClient, csr, certificatesv1.CertificateFailed, v.fieldManager)
		return err
	}

	log.V(logf.DebugLevel).Info("certificate issued")

	csr.Status.Certificate = certPEM
	csr, err = util.UpdateOrApplyStatus(ctx, v.certClient, csr, "", v.fieldManager)
	if err != nil {
		message := "Error updating certificate"
		v.recorder.Eventf(csr, corev1.EventTypeWarning, "ErrorUpdate", "%s: %s", message, err)
		return err
	}

	log.V(logf.DebugLevel).Info("vault certificate issued")
	v.recorder.Event(csr, corev1.EventTypeNormal, "CertificateIssued", "Certificate signed successfully")

	return nil
}
