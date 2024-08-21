/*
Copyright 2022 The cert-manager Authors.

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
	"fmt"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	clientv1 "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/util/workqueue"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmexperimental "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// handleSecretReferenceWorkFunc is a function that returns am informer event
// handler work function, which is used to sync CertificateSigningRequests that
// reference the synced Secret through the
// "experimental.cert-manager.io/private-key-secret-name" annotation.
func handleSecretReferenceWorkFunc(log logr.Logger,
	lister clientv1.CertificateSigningRequestLister,
	helper issuer.Helper,
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName],
	issuerOptions controllerpkg.IssuerOptions,
) func(obj any) {
	return func(obj any) {
		log := log.WithName("handleSecretReference")
		secret, ok := controllerpkg.ToSecret(obj)
		if !ok {
			log.Error(nil, "object is not a secret", "object", obj)
			return
		}
		log = logf.WithResource(log, secret)
		requests, err := certificateSigningRequestsForSecret(log, lister, helper, secret, issuerOptions)
		if err != nil {
			log.Error(err, "failed to determine affected certificate signing requests")
			return
		}
		for _, request := range requests {
			queue.Add(types.NamespacedName{
				Name:      request.Name,
				Namespace: request.Namespace,
			})
		}
	}
}

// certificateSigningRequestsForSecret returns a list of
// CertificateSigningRequests which reference an issuer in the same Namespace
// as the Secret (the resource Namespace in the case of ClusterIssuer) via the
// "experimental.cert-manager.io/private-key-secret-name" annotation, and the
// request targets a SelfSigned Issuer or Cluster Issuer.
func certificateSigningRequestsForSecret(log logr.Logger,
	lister clientv1.CertificateSigningRequestLister,
	helper issuer.Helper,
	secret *corev1.Secret,
	issuerOptions controllerpkg.IssuerOptions,
) ([]*certificatesv1.CertificateSigningRequest, error) {
	dbg := log.V(logf.DebugLevel)
	requests, err := lister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list certificate requests: %w", err)
	}

	dbg.Info("checking if self signed certificate signing requests reference secret")
	var affected []*certificatesv1.CertificateSigningRequest
	for _, request := range requests {
		ref, ok := util.SignerIssuerRefFromSignerName(request.Spec.SignerName)
		if !ok {
			dbg.Info("certificate signing request has malformed signer name,", "signerName", request.Spec.SignerName)
			continue
		}

		kind, ok := util.IssuerKindFromType(ref.Type)
		if !ok {
			dbg.Info("certificate signing request signerName type does not match 'issuers' or 'clusterissuers' so skipping processing")
			continue
		}

		issuerObj, err := helper.GetGenericIssuer(cmmeta.ObjectReference{
			Name:  ref.Name,
			Kind:  kind,
			Group: ref.Group,
		}, ref.Namespace)
		if k8sErrors.IsNotFound(err) {
			dbg.Info("issuer not found, skipping")
			continue
		}

		if err != nil {
			log.Error(err, "failed to get issuer")
			return nil, err
		}

		dbg = logf.WithRelatedResource(dbg, issuerObj)

		if secret.Namespace != issuerOptions.ResourceNamespace(issuerObj) {
			dbg.Info("issuer is not in the same namespace scope as the secret, skipping")
			continue
		}

		dbg.Info("ensuring issuer type matches this controller")

		issuerType, err := apiutil.NameForIssuer(issuerObj)
		if err != nil {
			dbg.Error(err, "failed to determine issuer type, skipping")
			continue
		}

		if issuerType == apiutil.IssuerSelfSigned &&
			request.GetAnnotations()[cmexperimental.CertificateSigningRequestPrivateKeyAnnotationKey] == secret.Name {
			dbg.Info("certificate request references secret, syncing")
			affected = append(affected, request)
		}
	}

	return affected, nil
}
