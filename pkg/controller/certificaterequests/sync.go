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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

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
	errorIssuerNotFound    = "IssuerNotFound"
	errorIssuerNotReady    = "IssuerNotReady"
	errorIssuerInit        = "IssuerInitError"
	errorSavingCertificate = "SaveCertError"

	errorCertificateSigningRequestNotFound = "CSRNotFound"
	errorCertificateSigningRequestParse    = "CSRParseError"

	errorCertificateNotExists = "CertNotExists"
	errorCertificateParse     = "CertParseError"

	reasonIssuingCertificate = "IssueCert"
	successCertificateIssued = "CertIssued"

	messageErrorSavingCertificate = "Error saving TLS certificate: "
)

var (
	certificateRequestGvk = v1alpha1.SchemeGroupVersion.WithKind("CertificateRequest")
)

func (c *controller) Sync(ctx context.Context, cr *v1alpha1.CertificateRequest) (err error) {
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
	if len(cr.Spec.CSRPEM) == 0 {
		return errors.New(errorCertificateSigningRequestNotFound)
	}

	csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.CSRPEM)
	if err != nil {
		return err
	}

	el := validation.ValidateCertificateRequest(crCopy)
	if len(el) > 0 {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, "BadConfig", "Resource validation failed: %v", el.ToAggregate())
		return nil
	}

	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.helper.GetGenericIssuer(crCopy.Spec.IssuerRef, crCopy.Namespace)
	if k8sErrors.IsNotFound(err) {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, errorIssuerNotFound, err.Error())
		return nil
	}
	if err != nil {
		return err
	}
	dbg.Info("Fetched issuer resource referenced by certificate request", "issuer_name", crCopy.Spec.IssuerRef.Name)

	issuerReady := apiutil.IssuerHasCondition(issuerObj, v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})
	if !issuerReady {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, errorIssuerNotReady, "Issuer %s not ready", issuerObj.GetObjectMeta().Name)
		return nil
	}

	i, err := c.issuerFactory.IssuerFor(issuerObj)
	if err != nil {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, errorIssuerInit, "Internal error initialising issuer: %v", err)
		return nil
	}

	el = validation.ValidateCertificateRequestForIssuer(crCopy, issuerObj)
	if len(el) > 0 {
		c.recorder.Eventf(crCopy, corev1.EventTypeWarning, "BadConfig", "Resource validation failed: %v", el.ToAggregate())
		return nil
	}

	if len(cr.Status.Certificate) == 0 {
		dbg.Info("Invoking sign function as existing certificate does not exist")
		return c.sign(ctx, i, crCopy, csr)
	}

	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}

	dbg.Info("Update certificate request status if required")
	c.setCertificateRequestStatus(crCopy, csr, cert)

	// TODO: Metrics??

	if cert == nil {
		dbg.Info("Invoking sign function as existing certificate does not exist")
		return c.sign(ctx, i, crCopy, csr)
	}

	dbg.Info("Certificate does not need updating.")

	return nil
}

// return an error on failure. If retrieval is succesful, the certificate data
// will be stored in the certificate request status
func (c *controller) sign(ctx context.Context, issuer issuer.Interface,
	cr *v1alpha1.CertificateRequest, csr *x509.CertificateRequest) error {
	log := logf.FromContext(ctx)

	resp, err := issuer.Sign(ctx, cr)
	if err != nil {
		log.Error(err, "error issuing certificate request")
		return err
	}

	// if the issuer has not returned any data, exit early
	if resp == nil {
		c.setCertificateRequestStatus(cr, nil, nil)
		return nil
	}

	if len(resp.Certificate) > 0 {
		cr.Status.Certificate = resp.Certificate
		cr.Status.CA = resp.CA

		c.recorder.Event(cr, corev1.EventTypeNormal, successCertificateIssued, "Certificate issued successfully")
	}

	cert, err := pki.DecodeX509CertificateBytes(resp.Certificate)
	if err != nil {
		return err
	}

	c.setCertificateRequestStatus(cr, csr, cert)

	return nil
}

// setCertificateRequestStatus will update the status subresource of the
// certificate reques. It will not actually submit the resource to the
// apiserver.
func (c *controller) setCertificateRequestStatus(cr *v1alpha1.CertificateRequest, csr *x509.CertificateRequest, cert *x509.Certificate) {
	if cert == nil {
		apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady, v1alpha1.ConditionFalse, "NotExists", "Certificate does not exist")
		return
	}

	// Derive & set 'Ready' condition on CertificateRequest resource
	matches, matchErrs := c.certificateMatchesSpec(cr, csr, cert)
	ready := v1alpha1.ConditionFalse
	reason := ""
	message := ""
	switch {
	case !matches:
		ready = v1alpha1.ConditionFalse
		reason = "DoesNotMatch"
		message = strings.Join(matchErrs, ", ")
	default:
		ready = v1alpha1.ConditionTrue
		reason = "Ready"
		message = "Certificate exists and is signed"
	}

	apiutil.SetCertificateRequestCondition(cr, v1alpha1.CertificateRequestConditionReady, ready, reason, message)

	return
}

func (c *controller) certificateMatchesSpec(cr *v1alpha1.CertificateRequest, csr *x509.CertificateRequest, cert *x509.Certificate) (bool, []string) {
	var errs []string

	if err := csr.CheckSignature(); err != nil {
		errs = append(errs, fmt.Sprintf("failed to validate certificate signing request signature: %s", err))
	}

	// CR spec will become immutable

	return len(errs) == 0, errs
}

func (c *controller) updateCertificateRequestStatus(ctx context.Context, old, new *v1alpha1.CertificateRequest) (*v1alpha1.CertificateRequest, error) {
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
