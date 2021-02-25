/*
Copyright 2020 The cert-manager Authors.

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
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	internalapi "github.com/cert-manager/cert-manager/pkg/internal/apis/certmanager"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/pkg/webhook"
)

var (
	certificateRequestGvk = v1.SchemeGroupVersion.WithKind(v1.CertificateRequestKind)
)

func (c *Controller) Sync(ctx context.Context, cr *v1.CertificateRequest) (err error) {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	if !(cr.Spec.IssuerRef.Group == "" || cr.Spec.IssuerRef.Group == certmanager.GroupName) {
		dbg.Info("certificate request issuerRef group does not match certmanager group so skipping processing")
		return nil
	}

	switch apiutil.CertificateRequestReadyReason(cr) {
	case v1.CertificateRequestReasonFailed:
		dbg.Info("certificate request Ready condition failed so skipping processing")
		return

	case v1.CertificateRequestReasonIssued:
		dbg.Info("certificate request Ready condition true so skipping processing")
		return
	}

	crCopy := cr.DeepCopy()

	defer func() {
		if _, saveErr := c.updateCertificateRequestStatusAndAnnotations(ctx, cr, crCopy); saveErr != nil {
			err = utilerrors.NewAggregate([]error{saveErr, err})
		}
	}()

	dbg.Info("fetching issuer object referenced by CertificateRequest")

	issuerObj, err := c.helper.GetGenericIssuer(crCopy.Spec.IssuerRef, crCopy.Namespace)
	if k8sErrors.IsNotFound(err) {
		c.reporter.Pending(crCopy, err, "IssuerNotFound",
			fmt.Sprintf("Referenced %q not found", apiutil.IssuerKind(crCopy.Spec.IssuerRef)))
		return nil
	}

	if err != nil {
		log.Error(err, "failed to get issuer")
		return err
	}

	log = logf.WithRelatedResource(log, issuerObj)
	dbg.Info("ensuring issuer type matches this controller")

	issuerType, err := apiutil.NameForIssuer(issuerObj)
	if err != nil {
		c.reporter.Pending(crCopy, err, "IssuerTypeMissing",
			"Missing issuer type")
		return nil
	}

	// This CertificateRequest is not meant for us, ignore
	if issuerType != c.issuerType {
		c.log.WithValues(
			logf.RelatedResourceKindKey, issuerType,
		).V(logf.DebugLevel).Info("issuer reference type does not match controller resource kind, ignoring")
		return nil
	}

	// check ready condition
	if !apiutil.IssuerHasCondition(issuerObj, v1.IssuerCondition{
		Type:   v1.IssuerConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		c.reporter.Pending(crCopy, nil, "IssuerNotReady",
			"Referenced issuer does not have a Ready status condition")
		return nil
	}

	dbg.Info("validating CertificateRequest resource object")

	el := webhook.ValidationRegistry.Validate(crCopy, internalapi.SchemeGroupVersion.WithKind("CertificateRequest"))
	if len(el) > 0 {
		c.reporter.Failed(crCopy, el.ToAggregate(), "BadConfig",
			"Resource validation failed")
		return nil
	}

	if len(crCopy.Status.Certificate) > 0 {
		dbg.Info("certificate field is already set in status so skipping processing")
		return nil
	}

	dbg.Info("invoking sign function as existing certificate does not exist")

	// Attempt to call the Sign function on our issuer
	resp, err := c.issuer.Sign(ctx, crCopy, issuerObj)
	if err != nil {
		log.Error(err, "error issuing certificate request")
		return err
	}

	// If the issuer has not returned any data we may be pending or failed. The
	// underlying issuer will have set the condition of pending or failed and we
	// should potentially wait for a re-sync.
	if resp == nil {
		return nil
	}

	// Update to status with the new given response.
	crCopy.Status.Certificate = resp.Certificate
	crCopy.Status.CA = resp.CA

	// invalid cert
	_, err = pki.DecodeX509CertificateBytes(crCopy.Status.Certificate)
	if err != nil {
		c.reporter.Failed(crCopy, err, "DecodeError", "Failed to decode returned certificate")
		return nil
	}

	// Set condition to Ready.
	c.reporter.Ready(crCopy)

	return nil
}

func (c *Controller) updateCertificateRequestStatusAndAnnotations(ctx context.Context, old, new *v1.CertificateRequest) (*v1.CertificateRequest, error) {
	log := logf.FromContext(ctx, "updateStatus")

	// if annotations changed we have to call .Update() and not .UpdateStatus()
	if !reflect.DeepEqual(old.Annotations, new.Annotations) {
		log.V(logf.DebugLevel).Info("updating resource due to change in annotations", "diff", pretty.Diff(old.Annotations, new.Annotations))
		return c.cmClient.CertmanagerV1().CertificateRequests(new.Namespace).Update(context.TODO(), new, metav1.UpdateOptions{})
	}

	oldBytes, _ := json.Marshal(old.Status)
	newBytes, _ := json.Marshal(new.Status)
	if reflect.DeepEqual(oldBytes, newBytes) {
		return nil, nil
	}

	log.V(logf.DebugLevel).Info("updating resource due to change in status", "diff", pretty.Diff(string(oldBytes), string(newBytes)))
	return c.cmClient.CertmanagerV1().CertificateRequests(new.Namespace).UpdateStatus(context.TODO(), new, metav1.UpdateOptions{})
}
