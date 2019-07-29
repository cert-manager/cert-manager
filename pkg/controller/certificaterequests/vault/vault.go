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

package vault

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"path"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/certutil"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/jetstack/cert-manager/pkg/controller/certificaterequests/util"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	CRControllerName = "certificaterequests-issuer-vault"
)

type Vault struct {
	// used to record Events about resources to the API
	recorder record.EventRecorder

	issuerOptions controllerpkg.IssuerOptions

	helper issuer.Helper
}

func init() {
	// create certificate request controller for ca issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		vault := NewVault(ctx)

		controller := certificaterequests.New(apiutil.IssuerVault, vault)

		c, err := controllerpkg.New(ctx, CRControllerName, controller)
		if err != nil {
			return nil, err
		}

		return c.Run, nil
	})
}

func NewVault(ctx *controllerpkg.Context) *Vault {
	return &Vault{
		recorder:      ctx.Recorder,
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		helper: issuer.NewHelper(
			ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers().Lister(),
			ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers().Lister(),
		),
	}
}

func (v *Vault) Sign(ctx context.Context, cr *v1alpha1.CertificateRequest) (*issuer.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")
	dbg := log.V(logf.DebugLevel)

	reporter := crutil.NewReporter(log, cr, v.recorder)

	issuerObj, err := v.helper.GetGenericIssuer(cr.Spec.IssuerRef, cr.Namespace)
	if err != nil {
		log = log.WithValues(
			logf.RelatedResourceNameKey, cr.Spec.IssuerRef.Name,
			logf.RelatedResourceKindKey, cr.Spec.IssuerRef.Kind,
		)

		if k8sErrors.IsNotFound(err) {
			reporter.WithLog(log).Pending(err, v1alpha1.CertificateRequestReasonPending,
				fmt.Sprintf("Referenced %s not found", apiutil.IssuerKind(cr.Spec.IssuerRef)))
			return nil, nil
		}

		reporter.WithLog(log).Pending(err, v1alpha1.CertificateRequestReasonPending,
			fmt.Sprintf("Referenced %s not found", apiutil.IssuerKind(cr.Spec.IssuerRef)))
		return nil, err
	}

	csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.CSRPEM)
	if err != nil {
		reporter.Failed(err, "ErrorrParsingCSR",
			fmt.Sprintf("Failed to decode CSR in spec: %s", err))
		return nil, nil
	}

	client, err := v.initVaultClient(cr, issuerObj)
	if err != nil {
		reporter.Failed(err, "ErrorVaultInit",
			fmt.Sprintf("Failed to initialise vault client: %s", err))
		return nil, nil
	}

	dbg.Info("Vault certificate request", "commonName", csr.Subject.CommonName,
		"altNames", csr.DNSNames, "ipSans", pki.IPAddressesToString(csr.IPAddresses))

	bundle, err := v.requestSign(cr, csr, client, issuerObj)
	if err != nil {
		reporter.Failed(err, "ErrorSigning",
			fmt.Sprintf("Vault failed to sign certificate: %s", err))
		return nil, nil
	}

	var caPem []byte = nil
	if len(bundle.CAChain) > 0 {
		caPem = []byte(bundle.CAChain[0])
	}

	return &issuer.IssueResponse{
		Certificate: []byte(bundle.ToPEMBundle()),
		CA:          caPem,
	}, nil
}

func (v *Vault) requestSign(cr *v1alpha1.CertificateRequest, csr *x509.CertificateRequest,
	client *vault.Client, issuerObj v1alpha1.GenericIssuer) (*certutil.CertBundle, error) {

	parameters := map[string]string{
		"common_name": csr.Subject.CommonName,
		"alt_names":   strings.Join(csr.DNSNames, ","),
		"ip_sans":     strings.Join(pki.IPAddressesToString(csr.IPAddresses), ","),
		"ttl":         cr.Spec.Duration.String(),
		"csr":         string(cr.Spec.CSRPEM),

		"exclude_cn_from_sans": "true",
	}

	url := path.Join("/v1", issuerObj.GetSpec().Vault.Path)

	request := client.NewRequest("POST", url)

	if err := request.SetJSONBody(parameters); err != nil {
		return nil, fmt.Errorf("failed to build vault request: %s", err)
	}

	resp, err := client.RawRequest(request)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign certificate by vault: %s", err)
	}

	defer resp.Body.Close()

	vaultResult := certutil.Secret{}
	resp.DecodeJSON(&vaultResult)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode response returned by vault: %s", err)
	}

	parsedBundle, err := certutil.ParsePKIMap(vaultResult.Data)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode response returned by vault: %s", err)
	}

	bundle, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("unable to convert certificate bundle to PEM bundle: %s", err.Error())
	}

	return bundle, nil
}
