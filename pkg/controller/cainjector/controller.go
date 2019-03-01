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

package cainjector

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	certctrl "github.com/jetstack/cert-manager/pkg/controller/certificates"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// WantInjectAnnotation is the annotation that specifies that a particular
	// object wants injection of CAs.  It takes the form of a reference to a certificate
	// as namespace/name.  The certificate is expected to have the is-serving-for annotations.
	WantInjectAnnotation = "certmanager.k8s.io/inject-ca-from"

	// WantInjectAPIServerCAAnnotation, if set to "true", will make the cainjector
	// inject the CA certificate for the Kubernetes apiserver into the resource.
	// It discovers the apiserver's CA by inspecting the service account credentials
	// mounted into the
	WantInjectAPIServerCAAnnotation = "certmanager.k8s.io/inject-apiserver-ca"
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
	lblVal, hasLbl := secret.Labels[certmanager.CertificateNameKey]
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
	AsObject() runtime.Object

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
}

// genericInjectReconciler is a reconciler that knows how to check if a given object is
// marked as requiring a CA, chase down the corresponding Service, Certificate, Secret, and
// inject that into the object.
type genericInjectReconciler struct {
	// injector is responsible for the logic of actually setting a CA -- it's the component
	// that contains type-specific logic.
	injector CertInjector

	log logr.Logger
	client.Client

	// apiserverCABundle is the ca bundle used by the apiserver.
	// This will be injected into resources that have the `
	apiserverCABundle []byte

	resourceName string // just used for logging
}

// InjectClient provides a client for this reconciler.
func (r *genericInjectReconciler) InjectClient(c client.Client) error {
	r.Client = c
	return nil
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
func (r *genericInjectReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.log.WithValues(r.resourceName, req.NamespacedName)

	// fetch the target object
	target := r.injector.NewTarget()
	if err := r.Client.Get(ctx, req.NamespacedName, target.AsObject()); err != nil {
		log.Error(err, "unable to fetch target object to inject into")
		return ctrl.Result{}, err
	}

	// ensure that it wants injection
	metaObj, err := meta.Accessor(target.AsObject())
	if err != nil {
		log.Error(err, "unable to get metadata for object")
		return ctrl.Result{}, err
	}
	certNameRaw := metaObj.GetAnnotations()[WantInjectAnnotation]
	hasInjectAPIServerCA := metaObj.GetAnnotations()[WantInjectAPIServerCAAnnotation] == "true"
	if certNameRaw != "" && hasInjectAPIServerCA {
		log.Info("object has both inject-ca-from and inject-apiserver-ca annotations, skipping")
		return ctrl.Result{}, nil
	}
	if hasInjectAPIServerCA {
		log.V(1).Info("setting apiserver ca bundle on injectable")
		target.SetCA(r.apiserverCABundle)

		// actually update with injected CA data
		if err := r.Client.Update(ctx, target.AsObject()); err != nil {
			log.Error(err, "unable to update target object with new CA data")
			return ctrl.Result{}, err
		}
		log.V(1).Info("updated object")
		return ctrl.Result{}, nil
	}
	if certNameRaw == "" {
		log.V(1).Info("object does not want CA injection, skipping")
		return ctrl.Result{}, nil
	}

	certName := splitNamespacedName(certNameRaw)
	log = log.WithValues("certificate", certName)
	if certName.Namespace == "" {
		log.Error(nil, "invalid certificate name")
		// don't return an error, requeuing won't help till this is changed
		return ctrl.Result{}, nil
	}

	var cert certmanager.Certificate
	if err := r.Client.Get(ctx, certName, &cert); err != nil {
		log.Error(err, "unable to fetch associated certificate")
		// don't requeue if we're just not found, we'll get called when the secret gets created
		return ctrl.Result{}, dropNotFound(err)
	}

	// grab the associated secret, and ensure it's owned by the cert
	secretName := types.NamespacedName{Namespace: cert.Namespace, Name: cert.Spec.SecretName}
	log = log.WithValues("secret", secretName)
	var secret corev1.Secret
	if err := r.Client.Get(ctx, secretName, &secret); err != nil {
		log.Error(err, "unable to fetch associated secret")
		// don't requeue if we're just not found, we'll get called when the secret gets created
		return ctrl.Result{}, dropNotFound(err)
	}
	owner := OwningCertForSecret(&secret)
	if owner == nil || *owner != certName {
		log.Info("refusing to target secret not owned by certificate", "owner", metav1.GetControllerOf(&secret))
		return ctrl.Result{}, nil
	}

	// inject the CA data
	caData, hasCAData := secret.Data[certctrl.TLSCAKey]
	if !hasCAData {
		log.Error(nil, "certificate has no CA data")
		// don't requeue, we'll get called when the secret gets updated
		return ctrl.Result{}, nil
	}

	// actually do the injection
	target.SetCA(caData)

	// actually update with injected CA data
	if err := r.Client.Update(ctx, target.AsObject()); err != nil {
		log.Error(err, "unable to update target object with new CA data")
		return ctrl.Result{}, err
	}
	log.V(1).Info("updated object")

	return ctrl.Result{}, nil
}
