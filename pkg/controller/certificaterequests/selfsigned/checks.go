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
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmdoc "github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	clientv1 "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// handleSecretReferenceWorkFunc is a function that returns am informer event
// handler work function, which is used to sync CertificateRequests that
// reference the synced Secret through the
// "cert-manager.io/private-key-secret-name" annotation.
func handleSecretReferenceWorkFunc(log logr.Logger,
	lister clientv1.CertificateRequestLister,
	helper issuer.Helper,
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName],
) func(obj any) {
	return func(obj any) {
		log := log.WithName("handleSecretReference")
		secret, ok := controllerpkg.ToSecret(obj)
		if !ok {
			log.Error(nil, "object is not a secret", "object", obj)
			return
		}
		log = logf.WithResource(log, secret)
		requests, err := certificateRequestsForSecret(log, lister, helper, secret)
		if err != nil {
			log.Error(err, "failed to determine affected certificate requests")
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

// certificateRequestsForSecret returns a list of CertificateRequests in the
// same Namespace as the given Secret, reference the given Secret via the
// "cert-manager.io/private-key-secret-name" annotation, and the request
// targets a SelfSigned Issuer or Cluster Issuer.
func certificateRequestsForSecret(log logr.Logger,
	lister clientv1.CertificateRequestLister,
	helper issuer.Helper,
	secret *corev1.Secret,
) ([]*cmapi.CertificateRequest, error) {
	dbg := log.V(logf.DebugLevel)
	requests, err := lister.CertificateRequests(secret.Namespace).List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list certificate requests: %w", err)
	}

	dbg.Info("checking if self signed certificate requests reference secret")
	var affected []*cmapi.CertificateRequest
	for _, request := range requests {
		if request.Spec.IssuerRef.Group != cmdoc.GroupName {
			dbg.Info("skipping SelfSigned secret reference checks since issuer has external group", "group", request.Spec.IssuerRef.Group)
			continue
		}

		issuerObj, err := helper.GetGenericIssuer(request.Spec.IssuerRef, request.Namespace)
		if k8sErrors.IsNotFound(err) {
			dbg.Info("issuer not found, skipping")
			continue
		}

		if err != nil {
			log.Error(err, "failed to get issuer")
			return nil, err
		}

		dbg = logf.WithRelatedResource(dbg, issuerObj)
		dbg.Info("ensuring issuer type matches this controller")

		issuerType, err := apiutil.NameForIssuer(issuerObj)
		if err != nil {
			dbg.Error(err, "failed to determine issuer type, skipping")
			continue
		}

		if issuerType == apiutil.IssuerSelfSigned &&
			request.GetAnnotations()[cmapi.CertificateRequestPrivateKeyAnnotationKey] == secret.Name {
			dbg.Info("certificate request references secret, syncing")
			affected = append(affected, request)
		}
	}

	return affected, nil
}
