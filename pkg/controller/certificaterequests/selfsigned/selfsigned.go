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

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/jetstack/cert-manager/pkg/controller/certificaterequests/util"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	cmerrors "github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	CRControllerName = "certificaterequests-issuer-selfsigned"
)

type SelfSigned struct {
	// used to record Events about resources to the API
	recorder record.EventRecorder

	issuerOptions controllerpkg.IssuerOptions
	secretsLister corelisters.SecretLister

	// Clock used to set constant time for testing
	clock clock.Clock
}

func init() {
	// create certificate request controller for selfsigned issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		selfsigned := NewSelfSigned(ctx)
		controller := certificaterequests.New(apiutil.IssuerSelfSigned, selfsigned)

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
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		clock:         ctx.Clock,
	}
}

func (s *SelfSigned) Sign(ctx context.Context, cr *v1alpha1.CertificateRequest, issuerObj v1alpha1.GenericIssuer) (*issuer.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")
	reporter := crutil.NewReporter(cr, s.clock, s.recorder)

	resourceNamespace := s.issuerOptions.ResourceNamespace(issuerObj)

	secretName, ok := cr.ObjectMeta.Annotations[v1alpha1.CRPrivateKeyAnnotationKey]
	if !ok || secretName == "" {
		message := fmt.Sprintf("Annotation %q missing or reference empty",
			v1alpha1.CRPrivateKeyAnnotationKey)
		err := errors.New("secret name missing")

		reporter.Failed(err, "MissingAnnotation", message)
		log.Error(err, message)

		return nil, nil
	}

	privatekey, err := kube.SecretTLSKey(ctx, s.secretsLister, cr.Namespace, secretName)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			message := fmt.Sprintf("Referenced secret %s/%s not found", cr.Namespace, secretName)

			reporter.Pending(err, "MissingSecret", message)
			log.Error(err, message)

			return nil, nil
		}

		if cmerrors.IsInvalidData(err) {
			message := fmt.Sprintf("Failed to get key %q referenced in annotation %q",
				secretName, v1alpha1.CRPrivateKeyAnnotationKey)

			reporter.Pending(err, "ErrorParsingKey", message)
			log.Error(err, message)

			return nil, nil
		}

		// We are probably in a network error here so we should backoff and retry
		message := fmt.Sprintf("Failed to get certificate key pair from secret %s/%s", resourceNamespace, secretName)
		reporter.Pending(err, "ErrorGettingSecret", message)
		log.Error(err, message)
		return nil, err
	}

	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		message := "Error generating certificate template"
		reporter.Failed(err, "ErrorGenerating", message)
		log.Error(err, message)
		return nil, nil
	}

	// extract the public component of the key
	publickey, err := pki.PublicKeyForPrivateKey(privatekey)
	if err != nil {
		message := "Failed to get public key from private key"
		reporter.Failed(err, "ErrorPublicKey", message)
		log.Error(err, message)
		return nil, nil
	}

	ok, err = pki.PublicKeysEqual(publickey, template.PublicKey)
	if err != nil || !ok {

		if err == nil {
			err = errors.New("CSR not signed by referenced private key")
		}

		message := "Error generating certificate template"
		reporter.Failed(err, "ErrorKeyMatch", message)
		log.Error(err, message)

		return nil, nil
	}

	// sign and encode the certificate
	certPem, _, err := pki.SignCertificate(template, template, publickey, privatekey)
	if err != nil {
		message := "Error signing certificate"
		reporter.Failed(err, "ErrorSigning", message)
		log.Error(err, message)
		return nil, nil
	}

	log.Info("self signed certificate issued")

	// We set the CA to the returned certificate here since this is self signed.
	return &issuer.IssueResponse{
		Certificate: certPem,
		CA:          certPem,
	}, nil
}
