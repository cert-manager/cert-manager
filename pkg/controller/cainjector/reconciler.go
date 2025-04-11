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

package cainjector

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/internal/cainjector/feature"
	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

// This file contains logic to create reconcilers. By default a
// reconciler is created for each of the injectables - CustomResourceDefinition,
// Validating/MutatingWebhookConfiguration, APIService and gets triggered for
// events on those resources as well as on Secrets and Certificates.

// reconciler syncs CA data from source to injectable.
type reconciler struct {
	// newInjectableTarget knows how to create a new injectable target for
	// the injectable being reconciled.
	newInjectableTarget NewInjectableTarget
	// sources is a list of available 'data sources' that can be used to extract
	// caBundles from various source.
	// This is defined as a variable to allow an instance of the secret-based
	// cainjector to run even when Certificate resources cannot we watched due to
	// the conversion webhook not being available.
	sources []caDataSource

	log logr.Logger
	client.Client

	// if set, the reconciler is namespace scoped
	namespace string

	// fieldManager is the manager name used for the Apply operations.
	fieldManager string

	resourceName string // just used for logging
}

// Reconcile attempts to ensure that a particular injectable has all the CAs injected that
// it has requested.
func (r *reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// fetch the target object
	target := r.newInjectableTarget()

	log := r.log.WithValues("kind", r.resourceName, "name", req.Name)
	log.V(logf.DebugLevel).Info("Parsing injectable")

	if err := r.Client.Get(ctx, req.NamespacedName, target.AsObject()); err != nil {
		if dropNotFound(err) == nil {
			// don't requeue on deletions, which yield a non-found object
			log.V(logf.DebugLevel).Info("ignoring", "reason", "not found", "err", err)
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch target object to inject into")
		return ctrl.Result{}, err
	}

	metaObj, err := meta.Accessor(target.AsObject())
	if err != nil {
		log.Error(err, "unable to get metadata for object")
		return ctrl.Result{}, err
	}

	// ignore resources that are being deleted
	if !metaObj.GetDeletionTimestamp().IsZero() {
		log.V(logf.DebugLevel).Info("ignoring", "reason", "object has a non-zero deletion timestamp")
		return ctrl.Result{}, nil
	}

	// ensure that it wants injection
	dataSource, err := r.caDataSourceFor(log, metaObj)
	if err != nil {
		log.V(logf.DebugLevel).Info("failed to determine ca data source for injectable")
		return ctrl.Result{}, nil
	}

	caData, err := dataSource.ReadCA(ctx, log, metaObj, r.namespace)
	if apierrors.IsForbidden(err) {
		log.V(logf.InfoLevel).Info("cainjector was forbidden to retrieve the ca data source")
		return ctrl.Result{}, nil
	}
	if err != nil {
		log.Error(err, "failed to read CA from data source")
		return ctrl.Result{}, err
	}

	if caData == nil {
		log.V(logf.InfoLevel).Info("could not find any ca data in data source for target")
		return ctrl.Result{}, nil
	}

	// actually do the injection
	target.SetCA(caData)

	// actually update with injected CA data
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		obj, patch := target.AsApplyObject()
		if patch != nil {
			err = r.Client.Patch(ctx, obj, patch, &client.PatchOptions{
				Force: ptr.To(true), FieldManager: r.fieldManager,
			})
		}
	} else {
		err = r.Client.Update(ctx, target.AsObject())
	}

	if err != nil {
		log.Error(err, "unable to update target object with new CA data")
		return ctrl.Result{}, err
	}

	log.V(logf.InfoLevel).Info("Updated object")

	return ctrl.Result{}, nil
}

func (r *reconciler) caDataSourceFor(log logr.Logger, metaObj metav1.Object) (caDataSource, error) {
	for _, s := range r.sources {
		if s.Configured(log, metaObj) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("could not determine ca data source for resource")
}

// dropNotFound ignores the given error if it's a not-found error,
// but otherwise just returns the argument.
// TODO: we don't use this pattern anywhere else in this project so probably doesn't make sense here either
func dropNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// owningCertForSecret gets the name of the owning certificate for a given
// secret, returning nil if the supplied secret does not have a
// `cert-manager.io/certificate-name` annotation.
// The secret may be a v1.Secret or a v1.PartialObjectMetadata.
//
// NOTE: "owning" here does not mean [ownerReference][1], because
// cert-manager does not set the ownerReference of the Secret,
// unless the [`--enable-certificate-owner-ref` flag is true][2].
//
// [1]: https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
// [2]: https://cert-manager.io/docs/cli/controller/
func owningCertForSecret(secret client.Object) *types.NamespacedName {
	val, ok := secret.GetAnnotations()[certmanager.CertificateNameKey]
	if !ok {
		return nil
	}
	return &types.NamespacedName{
		Name:      val,
		Namespace: secret.GetNamespace(),
	}
}

// splitNamespacedName turns the string form of a namespaced name
// (<namespace>/<name>) back into a types.NamespacedName.
func splitNamespacedName(nameStr string) types.NamespacedName {
	splitPoint := strings.IndexRune(nameStr, types.Separator)
	if splitPoint == -1 {
		return types.NamespacedName{Name: nameStr}
	}
	return types.NamespacedName{Namespace: nameStr[:splitPoint], Name: nameStr[splitPoint+1:]}
}
