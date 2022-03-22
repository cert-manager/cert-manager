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

package certificatesigningrequests

import (
	"context"
	"fmt"

	authzv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func (c *Controller) Sync(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) error {
	log := logf.WithResource(logf.FromContext(ctx), csr).WithValues("signerName", csr.Spec.SignerName)
	dbg := log.V(logf.DebugLevel)

	// Deep copy CertificateSigningRequest to prevent writing to the shared local
	// cache making it invalid. Done early in the sync to avoid accidental
	// invalidation by future contributions.
	csr = csr.DeepCopy()

	ref, ok := util.SignerIssuerRefFromSignerName(csr.Spec.SignerName)
	if !ok {
		dbg.Info("certificate signing request has malformed signer name,", "signerName", csr.Spec.SignerName)
		return nil
	}

	if ref.Group != certmanager.GroupName {
		dbg.Info("certificate signing request signerName group does not match 'cert-manager.io' group so skipping processing")
		return nil
	}

	if util.CertificateSigningRequestIsFailed(csr) {
		dbg.Info("certificate signing request has failed so skipping processing")
		return nil
	}
	if util.CertificateSigningRequestIsDenied(csr) {
		dbg.Info("certificate signing request has been denied so skipping processing")
		return nil
	}
	if !util.CertificateSigningRequestIsApproved(csr) {
		c.recorder.Event(csr, corev1.EventTypeNormal, "WaitingApproval", "Waiting for the Approved condition before issuing")
		dbg.Info("certificate signing request is not approved so skipping processing")
		return nil
	}

	if len(csr.Status.Certificate) > 0 {
		dbg.Info("certificate field is already set in status so skipping processing")
		return nil
	}

	kind, ok := util.IssuerKindFromType(ref.Type)
	if !ok {
		dbg.Info("certificate signing request signerName type does not match 'issuers' or 'clusterissuers' so skipping processing")
		return nil
	}

	issuerObj, err := c.helper.GetGenericIssuer(cmmeta.ObjectReference{
		Name:  ref.Name,
		Kind:  kind,
		Group: ref.Group,
	}, ref.Namespace)
	if apierrors.IsNotFound(err) {
		c.recorder.Eventf(csr, corev1.EventTypeWarning, "IssuerNotFound", "Referenced %s %s/%s not found", kind, ref.Namespace, ref.Name)
		return nil
	}

	if err != nil {
		log.Error(err, "failed to get issuer")
		return err
	}

	log = logf.WithRelatedResource(log, issuerObj)
	dbg.Info("ensuring issuer type matches this controller")

	signerType, err := apiutil.NameForIssuer(issuerObj)
	if err != nil {
		c.recorder.Eventf(csr, corev1.EventTypeWarning, "IssuerTypeMissing", "Referenced %s %s/%s is missing type", kind, ref.Namespace, ref.Name)
		return nil
	}

	// This CertificateSigningRequest is not meant for us, ignore
	if signerType != c.signerType {
		dbg.WithValues(logf.RelatedResourceKindKey, signerType).Info("signer reference type does not match controller resource kind, ignoring")
		return nil
	}

	if kind == cmapi.IssuerKind {
		ok, err := c.userCanReferenceSigner(ctx, csr, ref.Namespace, ref.Name)
		if err != nil {
			return err
		}

		if !ok {
			message := fmt.Sprintf("Requester may not reference Namespaced Issuer %s/%s", ref.Namespace, ref.Name)
			c.recorder.Event(csr, corev1.EventTypeWarning, "DeniedReference", message)
			util.CertificateSigningRequestSetFailed(csr, "DeniedReference", message)
			_, err := util.UpdateOrApplyStatus(ctx, c.certClient, csr, certificatesv1.CertificateFailed, c.fieldManager)
			return err
		}
	}

	duration, err := pki.DurationFromCertificateSigningRequest(csr)
	if err != nil {
		message := fmt.Sprintf("Failed to parse requested duration: %s", err)
		log.Error(err, message)
		c.recorder.Event(csr, corev1.EventTypeWarning, "ErrorParseDuration", message)
		util.CertificateSigningRequestSetFailed(csr, "ErrorParseDuration", message)
		_, err := util.UpdateOrApplyStatus(ctx, c.certClient, csr, certificatesv1.CertificateFailed, c.fieldManager)
		return err
	}

	// Enforce minimum duration of certificate to be 600s to ensure
	// compatibility with Certificate Signing Requests's
	// spec.expirationSeconds
	if duration < experimentalapi.CertificateSigningRequestMinimumDuration {
		message := fmt.Sprintf("CertificateSigningRequest minimum allowed duration is %s, requested %s", experimentalapi.CertificateSigningRequestMinimumDuration, duration)
		c.recorder.Event(csr, corev1.EventTypeWarning, "InvalidDuration", message)
		util.CertificateSigningRequestSetFailed(csr, "InvalidDuration", message)
		_, err := util.UpdateOrApplyStatus(ctx, c.certClient, csr, certificatesv1.CertificateFailed, c.fieldManager)
		return err

	}

	// check ready condition
	if !apiutil.IssuerHasCondition(issuerObj, cmapi.IssuerCondition{
		Type:   cmapi.IssuerConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		c.recorder.Eventf(csr, corev1.EventTypeWarning, "IssuerNotReady", "Referenced %s %s/%s does not have a Ready status condition",
			kind, issuerObj.GetNamespace(), issuerObj.GetName())
		return nil
	}

	dbg.Info("invoking sign function as existing certificate does not exist")

	return c.signer.Sign(ctx, csr, issuerObj)
}

// userCanReferenceSigner will return true if the CSR requester has a bound
// role that allows them to reference a given Namespaced signer. The user must
// have the permissions:
// group: cert-manager.io
// resource: signers
// verb: reference
// namespace: <referenced signer namespace>
// name: <either the name of the signer or '*' for all signer names in that namespace>
func (c *Controller) userCanReferenceSigner(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, issuerNamespace, issuerName string) (bool, error) {
	extra := make(map[string]authzv1.ExtraValue)
	for k, v := range csr.Spec.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}

	for _, name := range []string{issuerName, "*"} {
		resp, err := c.sarClient.Create(ctx, &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:   csr.Spec.Username,
				Groups: csr.Spec.Groups,
				Extra:  extra,
				UID:    csr.Spec.UID,

				ResourceAttributes: &authzv1.ResourceAttributes{
					Group:     certmanager.GroupName,
					Resource:  "signers",
					Verb:      "reference",
					Namespace: issuerNamespace,
					Name:      name,
					Version:   "*",
				},
			},
		}, metav1.CreateOptions{})
		if err != nil {
			return false, err
		}

		if resp.Status.Allowed {
			return true, nil
		}
	}

	return false, nil
}
