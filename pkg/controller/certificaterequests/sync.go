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
	"reflect"

	"github.com/kr/pretty"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorCertificateNotExists = "CertNotExists"
	errorCertificateParse     = "CertParseError"

	errorIssuerNotFound = "IssuerNotFound"
	errorIssuerInit     = "IssuerInitError"

	successCertificateIssued = "CertIssued"
)

func (c *Controller) Sync(ctx context.Context, cr *v1alpha1.CertificateRequest) (err error) {
	c.metrics.IncrementSyncCallCount(ControllerName)

	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	crCopy := cr.DeepCopy()
	defer func() {
		if _, saveErr := c.updateCertificateRequestStatus(ctx, cr, crCopy); saveErr != nil {
			err = utilerrors.NewAggregate([]error{saveErr, err})
		}
	}()

	dbg.Info("Fetching existing certificate signing request and certificate from certificate request",
		"name", crCopy.ObjectMeta.Name)

	issuerObj, err := c.helper.GetGenericIssuer(crCopy.Spec.IssuerRef, crCopy.Namespace)
	if k8sErrors.IsNotFound(err) {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, errorIssuerNotFound, err.Error())
		return nil
	}
	if err != nil {
		return err
	}

	issuerType, err := apiutil.NameForIssuer(issuerObj)
	if err != nil {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, errorIssuerNotFound, err.Error())
		return nil
	}

	// This CertificateRequest is not meant for us, ignore
	if issuerType != c.issuerType {
		log.V(5).Info("issuer reference type does not match resource kind, ignoring",
			"certificaterequest-issuer-type", issuerType,
			"issuer-type", c.issuerType)
		return nil
	}

	el := validation.ValidateCertificateRequest(crCopy)
	if len(el) > 0 {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, "BadConfig", "Resource validation failed: %v", el.ToAggregate())
		return nil
	}

	i, err := c.issuerFactory.IssuerFor(issuerObj)
	if err != nil {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, errorIssuerInit, "Internal error initialising issuer: %v", err)
		return nil
	}

	dbg.Info("Fetched issuer resource referenced by certificate request", "issuer_name", crCopy.Spec.IssuerRef.Name)

	if len(cr.Status.Certificate) == 0 {
		dbg.Info("Invoking sign function as existing certificate does not exist")
		return c.sign(ctx, crCopy, i)
	}

	dbg.Info("Update certificate request status if required")
	c.setCertificateRequestStatus(crCopy)

	// TODO: Metrics??

	dbg.Info("Certificate does not need updating.")

	return nil
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

		c.recorder.Event(cr, corev1.EventTypeNormal, successCertificateIssued, "Certificate issued successfully")
	}

	return nil
}

// setCertificateRequestStatus will update the status subresource of the
// certificate request.
func (c *Controller) setCertificateRequestStatus(cr *v1alpha1.CertificateRequest) {
	// No cert exists yet
	if len(cr.Status.Certificate) == 0 {
		apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady, v1alpha1.ConditionFalse,
			errorCertificateNotExists, "Certificate does not exist")
		return
	}

	// invalid cert
	_, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady,
			v1alpha1.ConditionFalse, errorCertificateParse, "Failed to decode certificate PEM")
		return
	}

	// cert exists and can be decoded so we are ready
	apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady,
		v1alpha1.ConditionTrue, "Ready", "Certificate exists and is signed")
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
