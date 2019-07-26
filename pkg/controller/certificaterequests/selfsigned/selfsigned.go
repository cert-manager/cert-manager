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
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/go-logr/logr"
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
	errorNoAnnotation = fmt.Errorf("self signed issuer requires %q annotation to be set to the name of the Secret containing the private key",
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
		s.reportPendingStatus(log, cr, errorNoAnnotation, "MissingAnnotation",
			fmt.Sprintf("Annotation %q missing or reference empty",
				v1alpha1.CRPrivateKeyAnnotationKey))

		return nil, nil
	}

	privatekey, err := kube.SecretTLSKey(ctx, s.secretsLister, cr.Namespace, skRef)
	if k8sErrors.IsNotFound(err) {
		s.reportPendingStatus(log, cr, err, "MissingSecret",
			fmt.Sprintf("Referenced secret %s/%s not found", cr.Namespace, skRef))

		return nil, nil
	}
	if err != nil {
		s.reportFaliedStatus(log, cr, err, "ErrorGettingKey",
			fmt.Sprintf("Failed to get key %q referenced in annotation %q",
				skRef, v1alpha1.CRPrivateKeyAnnotationKey))
		return nil, nil
	}

	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		s.reportFaliedStatus(log, cr, err, "ErrorGenerating", "Failed to generate certificate template")
		return nil, nil
	}

	// extract the public component of the key
	publickey, err := pki.PublicKeyForPrivateKey(privatekey)
	if err != nil {
		s.reportFaliedStatus(log, cr, err, "ErrorPublicKey", "Failed to get public key from private key")
		return nil, nil
	}

	ok, err = pki.PublicKeysEqual(publickey, template.PublicKey)
	if err != nil || !ok {

		if err == nil {
			err = errors.New("CSR not signed by referenced private key")
		}

		s.reportFaliedStatus(log, cr, err, "ErrorKeyMatch", "Error generating certificate template")

		return nil, nil
	}

	// sign and encode the certificate
	certPem, _, err := pki.SignCertificate(template, template, publickey, privatekey)
	if err != nil {
		s.reportFaliedStatus(log, cr, err, "ErrorSigning", "Error signing certificate")
		return nil, nil
	}

	log.Info("self signed certificate issued")

	// We set the CA to the returned certificate here since this is self signed.
	return &issuer.IssueResponse{
		Certificate: certPem,
		CA:          certPem,
	}, nil
}

func (s *SelfSigned) reportFaliedStatus(log logr.Logger, cr *v1alpha1.CertificateRequest, err error,
	reason, message string) {
	s.recorder.Event(cr, corev1.EventTypeWarning, reason, fmt.Sprintf("%s: %v", message, err))
	s.reportStatus(log, cr, err, reason, message, v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonFailed)
}

func (s *SelfSigned) reportPendingStatus(log logr.Logger, cr *v1alpha1.CertificateRequest, err error,
	reason, message string) {
	s.recorder.Event(cr, corev1.EventTypeNormal, reason, fmt.Sprintf("%s: %v", message, err))
	s.reportStatus(log, cr, err, reason, message, v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonPending)
}

func (s *SelfSigned) reportStatus(log logr.Logger, cr *v1alpha1.CertificateRequest, err error,
	reason, message string, condtion v1alpha1.ConditionStatus, reasonMessage v1alpha1.CertificateConditionType) {
	log.Error(err, message)

	// TODO: add mechanism here to handle invalid input errors which should result in a permanent failure
	apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady,
		v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonFailed,
		message)
}
