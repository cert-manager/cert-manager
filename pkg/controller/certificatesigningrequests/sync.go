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

	certificatesv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests/util"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

func (c *Controller) Sync(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (err error) {
	log := logf.WithResource(logf.FromContext(ctx), csr).WithValues("signerName", csr.Spec.SignerName)
	dbg := log.V(logf.DebugLevel)

	ref, ok := util.IssuerRefFromSignerName(csr.Spec.SignerName)
	if !ok {
		dbg.Info("certificate signing request has malformed signer name,", "signerName", csr.Spec.SignerName)
		return nil
	}

	if ref.Group != certmanager.GroupName {
		dbg.Info("certificate signing request signerName group does not match 'cert-manager.io' group so skipping processing")
		return nil
	}

	var kind string
	switch ref.Type {
	case "issuers":
		kind = cmapi.IssuerKind
	case "clusterissuers":
		kind = cmapi.ClusterIssuerKind
		if len(ref.Namespace) > 0 {
			// TODO: fail here
		}
	default:
		dbg.Info("certificate signing request signerName type does not match 'issuers' or 'clusterissuers' so skipping processing")
		return nil
	}

	if !util.CertificateSigningRequestIsApproved(csr) {
		dbg.Info("certificate signing request is not approved so skipping processing")
		return nil
	}
	if util.CertificateSigningRequestIsFailed(csr) {
		dbg.Info("certificate signing request has failed so skipping processing")
		return nil
	}

	fmt.Printf("%s\n", kind)

	issuerObj, err := c.helper.GetGenericIssuer(cmmeta.ObjectReference{
		Name:  ref.Name,
		Kind:  kind,
		Group: ref.Group,
	}, ref.Namespace)
	if apierrors.IsNotFound(err) {
		// TODO:
		//c.reporter.Pending(crCopy, err, "IssuerNotFound",
		//	fmt.Sprintf("Referenced %q not found", apiutil.IssuerKind(crCopy.Spec.IssuerRef)))
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
		// TODO:
		//c.reporter.Pending(crCopy, err, "IssuerTypeMissing",
		//	"Missing issuer type")
		return nil
	}

	// This CertificateSigningRequest is not meant for us, ignore
	if signerType != c.signerType {
		dbg.WithValues(logf.RelatedResourceKindKey, signerType).Info("signer reference type does not match controller resource kind, ignoring")
		return nil
	}

	if len(csr.Status.Certificate) > 0 {
		dbg.Info("certificate field is already set in status so skipping processing")
		return nil
	}

	//dbg.Info("invoking sign function as existing certificate does not exist")

	// check ready condition
	if !apiutil.IssuerHasCondition(issuerObj, cmapi.IssuerCondition{
		Type:   cmapi.IssuerConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		// TODO
		//c.reporter.Pending(crCopy, nil, "IssuerNotReady",
		//	"Referenced issuer does not have a Ready status condition")
		return nil
	}

	return c.signer.Sign(ctx, csr, issuerObj)
}
