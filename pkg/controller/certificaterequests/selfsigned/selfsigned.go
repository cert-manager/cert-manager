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

package selfsigned

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	CRControllerName = "certificaterequests-issuer-selfsigned"
)

var (
	errorNoAnnotation = fmt.Errorf("self signed issuer requires '%s' annotation set to secret name holding the private key",
		v1alpha1.CRPrivateKeyAnnotationKey)
)

type SelfSigned struct {
	// used to record Events about resources to the API
	recorder record.EventRecorder

	secretsLister corelisters.SecretLister
}

func init() {
	// create certificate request controller for selfsigned issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		selfsigned := NewSelfSigned(ctx)
		controller := certificaterequests.New(apiutil.IssuerCA, selfsigned)

		c, err := controllerpkg.New(ctx, CRControllerName, controller)
		if err != nil {
			return nil, err
		}

		return c.Run, nil
	})
}

func NewSelfSigned(ctx *controllerpkg.Context) *SelfSigned {
	return &SelfSigned{
		recorder:      ctx.Recorder,
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
	}
}

func (s *SelfSigned) Sign(ctx context.Context, cr *v1alpha1.CertificateRequest) (*issuer.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")

	skRef, ok := cr.ObjectMeta.Annotations[v1alpha1.CRPrivateKeyAnnotationKey]
	if !ok || skRef == "" {
		return nil, errorNoAnnotation
	}

	sk, err := kube.SecretTLSKey(ctx, s.secretsLister, cr.Namespace, skRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key %s referenced in the annotation '%s': %s",
			skRef, v1alpha1.CRPrivateKeyAnnotationKey, err)
	}

	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		log.Error(err, "error generating certificate template")
		s.recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error generating certificate template: %v", err)
		return nil, err
	}

	// extract the public component of the key
	pk, err := pki.PublicKeyForPrivateKey(sk)
	if err != nil {
		log.Error(err, "failed to get public key from private key")
		return nil, err
	}

	ok, err = pki.PublicKeyMatchesPublicKey(pk, template.PublicKey)
	if err != nil {
		log.Error(err, "failed to verify CSR is signed by referenced private key")
		return nil, err
	}

	if !ok {
		return nil, errors.New("CSR not signed by referenced private key")
	}

	// sign and encode the certificate
	certPem, _, err := pki.SignCertificate(template, template, pk, sk)
	if err != nil {
		s.recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error signing certificate: %v", err)
		return nil, err
	}

	log.Info("self signed certificate issued")

	return &issuer.IssueResponse{
		Certificate: certPem,
		CA:          certPem,
	}, nil
}
