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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// dropNotFound ignores the given error if it's a not-found error,
// but otherwise just returns the argument.
func dropNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// OwningCertForSecret gets the name of the owning certificate for a
// given secret, returning nil if no such object exists.
// Right now, this actually uses a label instead of owner refs,
// since certmanager doesn't set owner refs on secrets.
func OwningCertForSecret(secret *corev1.Secret) *types.NamespacedName {
	lblVal, hasLbl := secret.Annotations[certmanager.CertificateNameKey]
	if !hasLbl {
		return nil
	}
	return &types.NamespacedName{
		Name:      lblVal,
		Namespace: secret.Namespace,
	}
}

// InjectTarget is a Kubernetes API object that has one or more references to Kubernetes
// Services with corresponding fields for CA bundles.
type InjectTarget interface {
	// AsObject returns this injectable as an object.
	// It should be a pointer suitable for mutation.
	AsObject() client.Object

	// SetCA sets the CA of this target to the given certificate data (in the standard
	// PEM format used across Kubernetes).  In cases where multiple CA fields exist per
	// target (like admission webhook configs), all CAs are set to the given value.
	SetCA(data []byte)
}

// Injectable is a point in a Kubernetes API object that represents a Kubernetes Service
// reference with a corresponding spot for a CA bundle.
type Injectable interface {
}

// CertInjector knows how to create an instance of an InjectTarget for some particular type
// of inject target.  For instance, an implementation might create a InjectTarget
// containing an empty MutatingWebhookConfiguration.  The underlying API object can
// be populated (via AsObject) using client.Client#Get, and then CAs can be injected with
// Injectables (representing the various individual webhooks in the config) retrieved with
// Services.
type CertInjector interface {
	// NewTarget creates a new InjectTarget containing an empty underlying object.
	NewTarget() InjectTarget
	// IsAlpha tells the client to disregard "no matching kind" type of errors
	IsAlpha() bool
}

// genericInjectReconciler is a reconciler that knows how to check if a given object is
// marked as requiring a CA, chase down the corresponding Service, Certificate, Secret, and
// inject that into the object.
type genericInjectReconciler struct {
	// injector is responsible for the logic of actually setting a CA -- it's the component
	// that contains type-specific logic.
	injector CertInjector
	// sources is a list of available 'data sources' that can be used to extract
	// caBundles from various source.
	// This is defined as a variable to allow an instance of the secret-based
	// cainjector to run even when Certificate resources cannot we watched due to
	// the conversion webhook not being available.
	sources []caDataSource

	log logr.Logger
	client.Client

	resourceName string // just used for logging
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

// Reconcile attempts to ensure that a particular object has all the CAs injected that
// it has requested.
func (r *genericInjectReconciler) Reconcile(_ context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.log.WithValues(r.resourceName, req.NamespacedName)

	// fetch the target object
	target := r.injector.NewTarget()
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
	log = logf.WithResource(r.log, metaObj)

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

	caData, err := dataSource.ReadCA(ctx, log, metaObj)
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
	if err := r.Client.Update(ctx, target.AsObject()); err != nil {
		log.Error(err, "unable to update target object with new CA data")
		return ctrl.Result{}, err
	}
	log.V(logf.InfoLevel).Info("updated object")

	return ctrl.Result{}, nil
}

func (r *genericInjectReconciler) caDataSourceFor(log logr.Logger, metaObj metav1.Object) (caDataSource, error) {
	for _, s := range r.sources {
		if s.Configured(log, metaObj) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("could not determine ca data source for resource")
}
