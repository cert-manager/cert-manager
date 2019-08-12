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

package certificaterequests

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/kr/pretty"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func (c *Controller) Sync(ctx context.Context, cr *v1alpha1.CertificateRequest) (err error) {
	c.metrics.IncrementSyncCallCount(ControllerName)

	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	if !(cr.Spec.IssuerRef.Group == "" || cr.Spec.IssuerRef.Group == certmanager.GroupName) {
		dbg.Info("certificate request issuerRef group does not match certmanager group so skipping processing")
		return nil
	}

	if apiutil.CertificateRequestHasFailed(cr) {
		dbg.Info("certificate request condition failed so skipping processing")
		return nil
	}

	crCopy := cr.DeepCopy()

	defer func() {
		if _, saveErr := c.updateCertificateRequestStatus(ctx, cr, crCopy); saveErr != nil {
			err = utilerrors.NewAggregate([]error{saveErr, err})
		}
	}()

	// If the CertificateRequest has the conditon 'Failed' then set the
	// FailureTime to `c.clock.Now()`
	defer c.setFailureTime(crCopy)

	dbg.Info("fetching issuer object referenced by CertificateRequest")

	issuerObj, err := c.helper.GetGenericIssuer(crCopy.Spec.IssuerRef, crCopy.Namespace)
	if k8sErrors.IsNotFound(err) {
		apiutil.SetCertificateRequestCondition(crCopy, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonPending,
			fmt.Sprintf("Referenced %s not found", apiutil.IssuerKind(crCopy.Spec.IssuerRef)))

		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, v1alpha1.CertificateRequestReasonPending, err.Error())

		log.WithValues(
			logf.RelatedResourceNameKey, crCopy.Spec.IssuerRef.Name,
			logf.RelatedResourceKindKey, crCopy.Spec.IssuerRef.Kind,
		).Error(err, "failed to find referenced issuer")

		return nil
	}

	if err != nil {
		return err
	}

	dbg.Info("ensuring issuer type matches this controller")

	log = logf.WithRelatedResource(log, issuerObj)

	issuerType, err := apiutil.NameForIssuer(issuerObj)
	if err != nil {
		apiutil.SetCertificateRequestCondition(crCopy, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonPending,
			fmt.Sprintf("Referenced %s not found", apiutil.IssuerKind(crCopy.Spec.IssuerRef)))

		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, v1alpha1.CertificateRequestReasonPending, err.Error())
		log.Error(err, "failed to obtain referenced issuer type")
		return nil
	}

	// This CertificateRequest is not meant for us, ignore
	if issuerType != c.issuerType {
		c.log.WithValues(
			logf.RelatedResourceKindKey, issuerType,
		).V(5).Info("issuer reference type does not match controller resource kind, ignoring")
		return nil
	}

	dbg.Info("validating CertificateRequest resource object")

	el := validation.ValidateCertificateRequest(crCopy)
	if len(el) > 0 {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, "BadConfig", "Resource validation failed: %v", el.ToAggregate())

		apiutil.SetCertificateRequestCondition(crCopy, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonFailed, fmt.Sprintf("Validation failed: %s", el.ToAggregate()))
		return nil
	}

	defer c.setCertificateRequestStatus(crCopy)

	if len(crCopy.Status.Certificate) > 0 {
		dbg.Info("certificate field is already set in status so skipping processing")
		return nil
	}

	// TODO: Metrics??

	dbg.Info("invoking sign function as existing certificate does not exist")

	// Attempt to call the Sign function on our issuer
	resp, err := c.issuer.Sign(ctx, crCopy, issuerObj)
	if err != nil {
		log.Error(err, "error issuing certificate request")
		return err
	}

	// If the issuer has not returned any data, exit early as nil. Wait for the
	// next re-sync.
	if resp == nil {
		return nil
	}

	// Update to status with the new given certificate.
	if len(resp.Certificate) > 0 {
		crCopy.Status.Certificate = resp.Certificate
		crCopy.Status.CA = resp.CA

		c.recorder.Event(crCopy, corev1.EventTypeNormal, v1alpha1.CertificateRequestReasonIssued,
			"Certificate fetched from issuer successfully")
	}

	return nil
}

// setCertificateRequestStatus will update the status subresource of the
// certificate request.
func (c *Controller) setCertificateRequestStatus(cr *v1alpha1.CertificateRequest) {
	// No cert exists yet
	if len(cr.Status.Certificate) == 0 {
		apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonPending, "Certificate issuance pending")
		return
	}

	// invalid cert
	_, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, v1alpha1.CertificateRequestReasonFailed, "Failed to decode certificate PEM")
		return
	}

	// cert has been issued and can be decoded so we are ready
	apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady,
		v1alpha1.ConditionTrue, "Ready", "Certificate has been issued successfully")
	return
}

func (c *Controller) updateCertificateRequestStatus(ctx context.Context, old, new *v1alpha1.CertificateRequest) (*v1alpha1.CertificateRequest, error) {
	log := logf.FromContext(ctx, "updateStatus")
	oldBytes, _ := json.Marshal(old.Status)
	newBytes, _ := json.Marshal(new.Status)
	if reflect.DeepEqual(oldBytes, newBytes) {
		return nil, nil
	}

	log.V(logf.DebugLevel).Info("updating resource due to change in status", "diff", pretty.Diff(string(oldBytes), string(newBytes)))
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	return c.cmClient.CertmanagerV1alpha1().CertificateRequests(new.Namespace).Update(new)
}

// If the CertificateRequest has a condition set to 'Failed` then set the
// FailureTime to c.clock.Now(), only if it has not been already set.
func (c *Controller) setFailureTime(cr *v1alpha1.CertificateRequest) {
	if apiutil.CertificateRequestHasFailed(cr) {
		if cr.Status.FailureTime == nil {
			nowTime := metav1.NewTime(c.clock.Now())
			cr.Status.FailureTime = &nowTime
		}
	}
}
