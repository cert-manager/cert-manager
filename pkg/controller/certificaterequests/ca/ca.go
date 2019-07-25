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

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	issuerpkg "github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
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

func (c *CA) Sign(ctx context.Context, cr *v1alpha1.CertificateRequest) (*issuerpkg.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")

	issuer, err := c.helper.GetGenericIssuer(cr.Spec.IssuerRef, cr.Namespace)
	if k8sErrors.IsNotFound(err) {
		apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonPending,
			fmt.Sprintf("Referenced %s not found", apiutil.IssuerKind(cr.Spec.IssuerRef)))

		c.recorder.Event(cr, corev1.EventTypeWarning, v1alpha1.CertificateRequestReasonPending, err.Error())

		log.WithValues(
			logf.RelatedResourceNameKey, cr.Spec.IssuerRef.Name,
			logf.RelatedResourceKindKey, cr.Spec.IssuerRef.Kind,
		).Error(err, "failed to find referenced issuer")

		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	resourceNamespace := c.issuerOptions.ResourceNamespace(issuer)

	// get a copy of the CA certificate named on the Issuer
	caCerts, caKey, err := kube.SecretTLSKeyPair(ctx, c.secretsLister, resourceNamespace, issuer.GetSpec().CA.SecretName)
	if k8sErrors.IsNotFound(err) {
		log := logf.WithRelatedResourceName(log, issuer.GetSpec().CA.SecretName, resourceNamespace, "Secret")
		log.Info("error getting signing CA for Issuer")

		c.recorder.Event(cr, corev1.EventTypeWarning, v1alpha1.CertificateRequestReasonPending, err.Error())

		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonFailed,
			fmt.Sprintf("Failed to generate certificate template: %s", err))

		// TODO: add mechanism here to handle invalid input errors which should result in a permanent failure
		log.Error(err, "error generating certificate template")
		c.recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error generating certificate template: %v", err)
		return nil, nil
	}

	certPEM, caPEM, err := pki.SignCSRTemplate(caCerts, caKey, template)
	if err != nil {
		log.Error(err, "error signing certificate")
		c.recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error signing certificate: %v", err)
		return nil, err
	}

	log.Info("certificate issued")

	return &issuerpkg.IssueResponse{
		Certificate: certPEM,
		CA: caPEM,
	}, nil
}
