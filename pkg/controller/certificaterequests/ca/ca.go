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

package ca

import (
	"context"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/jetstack/cert-manager/pkg/controller/certificaterequests/util"
	issuerpkg "github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	cmerrors "github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	CRControllerName = "certificaterequests-issuer-ca"
)

type CA struct {
	// used to record Events about resources to the API
	recorder record.EventRecorder

	issuerOptions controllerpkg.IssuerOptions
	secretsLister corelisters.SecretLister
	helper        issuerpkg.Helper
}

func init() {
	// create certificate request controller for ca issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		ca := NewCA(ctx)

		controller := certificaterequests.New(apiutil.IssuerCA, ca)

		c, err := controllerpkg.New(ctx, CRControllerName, controller)
		if err != nil {
			return nil, err
		}

		return c.Run, nil
	})
}

func NewCA(ctx *controllerpkg.Context) *CA {
	return &CA{
		recorder:      ctx.Recorder,
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		helper: issuerpkg.NewHelper(
			ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers().Lister(),
			ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers().Lister(),
		),
	}
}

func (c *CA) Sign(ctx context.Context, cr *v1alpha1.CertificateRequest, issuerObj v1alpha1.GenericIssuer) (*issuerpkg.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")
	reporter := crutil.NewReporter(log, cr, c.recorder)

	secretName := issuerObj.GetSpec().CA.SecretName
	resourceNamespace := c.issuerOptions.ResourceNamespace(issuerObj)

	// get a copy of the CA certificate named on the Issuer
	caCerts, caKey, err := kube.SecretTLSKeyPair(ctx, c.secretsLister, resourceNamespace, issuerObj.GetSpec().CA.SecretName)
	if err != nil {
		log := logf.WithRelatedResourceName(log, issuerObj.GetSpec().CA.SecretName, resourceNamespace, "Secret")
		reporter = reporter.WithLog(log)

		if k8sErrors.IsNotFound(err) {
			reporter.Pending(err, "MissingSecret",
				fmt.Sprintf("Referenced secret %s/%s not found", resourceNamespace, secretName))

			return nil, nil
		}

		if cmerrors.IsInvalidData(err) {
			reporter.Pending(err, "ErrorParsingSecret",
				fmt.Sprintf("Failed to parse key cert pair from secret %s/%s", resourceNamespace, secretName))
			return nil, nil
		}

		// We are probably in a network error here so we should backoff and retry
		reporter.Pending(err, "ErrorGettingSecret",
			fmt.Sprintf("Failed to get key cert pair from secret %s/%s", resourceNamespace, secretName))
		return nil, err
	}

	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		reporter.Failed(err, "ErrorSigning", "Error generating certificate template")
		return nil, nil
	}

	certPEM, caPEM, err := pki.SignCSRTemplate(caCerts, caKey, template)
	if err != nil {
		reporter.Failed(err, "ErrorSigning", "Error signing certificate")
		return nil, err
	}

	log.Info("certificate issued")

	return &issuerpkg.IssueResponse{
		Certificate: certPEM,
		CA:          caPEM,
	}, nil
}
