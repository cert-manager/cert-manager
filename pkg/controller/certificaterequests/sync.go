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
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	reasonPending = "Pending"
	reasonFailed  = "Failed"
	reasonIssued  = "Issued"
)

func (c *Controller) Sync(ctx context.Context, cr *v1alpha1.CertificateRequest) (err error) {
	c.metrics.IncrementSyncCallCount(ControllerName)

	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	if !(cr.Spec.IssuerRef.Group == "" || cr.Spec.IssuerRef.Group == certmanager.GroupName) {
		dbg.Info("certificate request issuerRef group does not match certmanager group so skipping processing")
		return nil
	}

	if apiutil.CertificateRequestHasCondition(cr, v1alpha1.CertificateRequestCondition{
		Type:   v1alpha1.CertificateRequestConditionReady,
		Status: v1alpha1.ConditionFalse,
		Reason: reasonFailed,
	}) {
		dbg.Info("certificate request condition failed so skipping processing")
		return nil
	}

	crCopy := cr.DeepCopy()
	defer func() {
		if _, saveErr := c.updateCertificateRequestStatus(ctx, cr, crCopy); saveErr != nil {
			err = utilerrors.NewAggregate([]error{saveErr, err})
		}
	}()

	dbg.Info("fetching issuer object referenced by CertificateRequest")

	issuerObj, err := c.helper.GetGenericIssuer(crCopy.Spec.IssuerRef, crCopy.Namespace)
	if k8sErrors.IsNotFound(err) {
		apiutil.SetCertificateRequestCondition(crCopy, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, reasonPending,
			fmt.Sprintf("Referenced %s not found", issuerKind(crCopy)))

		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, reasonPending, err.Error())

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
			v1alpha1.ConditionFalse, reasonPending,
			fmt.Sprintf("Referenced %s not found", issuerKind(crCopy)))

		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, reasonPending, err.Error())
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
			v1alpha1.ConditionFalse, reasonFailed, fmt.Sprintf("Validation failed: %s", el.ToAggregate()))
		return nil
	}

	if len(crCopy.Status.Certificate) > 0 {
		dbg.Info("certificate field is already set in status so skipping processing")
		c.setCertificateRequestStatus(crCopy)
		return nil
	}

	i, err := c.issuerFactory.IssuerFor(issuerObj)
	if err != nil {
		apiutil.SetCertificateRequestCondition(crCopy, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, reasonFailed,
			fmt.Sprintf("Failed to initialise Issuer for signing: %s", err))

		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, reasonFailed, "Internal error initialising issuer: %v", err)
		return nil
	}

	// TODO: Metrics??

	dbg.Info("invoking sign function as existing certificate does not exist")
	return c.sign(ctx, crCopy, i)
}

// return an error on failure. If retrieval is succesful, the certificate data
// will be stored in the certificate request status
func (c *Controller) sign(ctx context.Context, cr *v1alpha1.CertificateRequest, issuer issuer.Interface) error {
	log := logf.FromContext(ctx)

	defer c.setCertificateRequestStatus(cr)

	resp, err := issuer.Sign(ctx, cr)
	if err != nil {
		log.Error(err, "error issuing certificate request")
		return err
	}

	// if the issuer has not returned any data, exit early
	if resp == nil {
		return nil
	}

	if len(resp.Certificate) > 0 {
		cr.Status.Certificate = resp.Certificate
		cr.Status.CA = resp.CA

		c.recorder.Event(cr, corev1.EventTypeNormal, reasonIssued,
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
			v1alpha1.ConditionFalse, reasonPending, "Certificate issuance pending")
		return
	}

	// invalid cert
	_, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, reasonFailed, "Failed to decode certificate PEM")
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

// issuerKind returns the kind of issuer for a certificaterequest
func issuerKind(cr *v1alpha1.CertificateRequest) string {
	if cr.Spec.IssuerRef.Kind == "" {
		return v1alpha1.IssuerKind
	}
	return cr.Spec.IssuerRef.Kind
}
