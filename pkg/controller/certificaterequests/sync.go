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
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/validation"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

var (
	certificateRequestGvk = v1alpha2.SchemeGroupVersion.WithKind(v1alpha2.CertificateRequestKind)
)

func (c *Controller) Sync(ctx context.Context, cr *v1alpha2.CertificateRequest) (err error) {
	c.metrics.IncrementSyncCallCount(ControllerName)

	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	if !(cr.Spec.IssuerRef.Group == "" || cr.Spec.IssuerRef.Group == certmanager.GroupName) {
		dbg.Info("certificate request issuerRef group does not match certmanager group so skipping processing")
		return nil
	}

	switch apiutil.CertificateRequestReadyReason(cr) {
	case v1alpha2.CertificateRequestReasonFailed:
		dbg.Info("certificate request Ready condition failed so skipping processing")
		return

	case v1alpha2.CertificateRequestReasonIssued:
		dbg.Info("certificate request Ready condition true so skipping processing")
		return
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
		).V(5).Info("issuer reference type does not match controller resource kind, ignoring")
		return nil
	}

	dbg.Info("validating CertificateRequest resource object")

	el := validation.ValidateCertificateRequest(crCopy)
	if len(el) > 0 {
		c.reporter.Failed(crCopy, el.ToAggregate(), "BadConfig",
			"Resource validation failed")
		return nil
	}

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

func (c *Controller) updateCertificateRequestStatus(ctx context.Context, old, new *v1alpha2.CertificateRequest) (*v1alpha2.CertificateRequest, error) {
	log := logf.FromContext(ctx, "updateStatus")
	oldBytes, _ := json.Marshal(old.Status)
	newBytes, _ := json.Marshal(new.Status)
	if reflect.DeepEqual(oldBytes, newBytes) {
		return nil, nil
	}

	log.V(logf.DebugLevel).Info("updating resource due to change in status", "diff", pretty.Diff(string(oldBytes), string(newBytes)))
	return c.cmClient.CertmanagerV1alpha2().CertificateRequests(new.Namespace).UpdateStatus(new)
}
