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

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

const (
	// injectFromPath is the index key used to look up the value of inject-ca-from on targeted objects
	injectFromPath = ".metadata.annotations.inject-ca-from"

	// injectFromSecretPath is the index key used to look up the value of
	// inject-ca-from-secret on targeted objects
	injectFromSecretPath = ".metadata.annotations.inject-ca-from-secret"
)

// certFromSecretToInjectableMapFuncBuilder returns a handler.MapFunc that, for
// a Secret change, ensures that if this Secret is a Certificate Secret of
// Certificate that is configured as a CA source for an injectable via
// inject-ca-from annotation, a reconcile loop will be triggered for this
// injectable
func certFromSecretToInjectableMapFuncBuilder(cl client.Reader, log logr.Logger, config setup) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []ctrl.Request {
		secretName := types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}
		certName := owningCertForSecret(obj.(*metav1.PartialObjectMetadata))
		if certName == nil {
			return nil
		}
		log := log.WithValues("type", config.resourceName, "secret", secretName, "certificate", *certName)

		// confirm that a service owns this cert
		var cert cmapi.Certificate
		if err := cl.Get(ctx, *certName, &cert); err != nil {
			// TODO(directxman12): check for not found error?
			log.Error(err, "unable to fetch certificate that owns the secret")
			return nil
		}

		objs := config.listType.DeepCopyObject().(client.ObjectList)
		if err := cl.List(ctx, objs, client.MatchingFields{injectFromPath: certName.String()}); err != nil {
			log.Error(err, "unable to fetch injectables associated with certificate")
			return nil
		}

		var reqs []ctrl.Request
		if err := meta.EachListItem(objs, func(obj runtime.Object) error {
			metaInfo, err := meta.Accessor(obj)
			if err != nil {
				log.Error(err, "unable to get metadata from list item")
				// continue on error
				return nil
			}
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{
				Name:      metaInfo.GetName(),
				Namespace: metaInfo.GetNamespace(),
			}})
			return nil
		}); err != nil {
			log.Error(err, "unable get items from list")
			return nil
		}

		return reqs
	}
}

// certToInjectableMapFuncBuilder returns a handler.MapFunc that, for
// a Certificate change, ensures that if this Certificate that is configured as
// a CA source for an injectable via inject-ca-from annotation, a reconcile loop
// will be triggered for this injectable
func certToInjectableMapFuncBuilder(cl client.Reader, log logr.Logger, config setup) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []ctrl.Request {
		certName := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
		log := log.WithValues("type", config.resourceName, "certificate", certName)
		objs := config.listType.DeepCopyObject().(client.ObjectList)
		if err := cl.List(ctx, objs, client.MatchingFields{injectFromPath: certName.String()}); err != nil {
			log.Error(err, "unable to fetch injectables associated with certificate")
			return nil
		}

		var reqs []ctrl.Request
		if err := meta.EachListItem(objs, func(obj runtime.Object) error {
			metaInfo, err := meta.Accessor(obj)
			if err != nil {
				log.Error(err, "unable to get metadata from list item")
				// continue on error
				return nil
			}
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{
				Name:      metaInfo.GetName(),
				Namespace: metaInfo.GetNamespace(),
			}})
			return nil
		}); err != nil {
			log.Error(err, "unable get items from list")
			return nil
		}

		return reqs
	}
}

// secretForInjectableMapFuncBuilder returns a handler.MapFunc that, for a
// config for particular injectable type (i.e CRD, APIService) and a Secret,
// returns all injectables that have the inject-ca-from-secret annotation with the
// given secret name. This will be used in an event handler to ensure that
// changes to a Secret triggers a reconcile loop for the relevant injectable.
func secretForInjectableMapFuncBuilder(cl client.Reader, log logr.Logger, config setup) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []ctrl.Request {
		secretName := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
		log := log.WithValues("type", config.resourceName, "secret", secretName)
		objs := config.listType.DeepCopyObject().(client.ObjectList)
		// TODO: ensure that this is cache lister, not a direct client
		if err := cl.List(ctx, objs, client.MatchingFields{injectFromSecretPath: secretName.String()}); err != nil {
			log.Error(err, "unable to fetch injectables associated with secret")
			return nil
		}

		var reqs []ctrl.Request
		if err := meta.EachListItem(objs, func(obj runtime.Object) error {
			metaInfo, err := meta.Accessor(obj)
			if err != nil {
				log.Error(err, "unable to get metadata from list item")
				// continue on error
				return nil
			}
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{
				Name:      metaInfo.GetName(),
				Namespace: metaInfo.GetNamespace(),
			}})
			return nil
		}); err != nil {
			log.Error(err, "unable get items from list")
			return nil
		}

		return reqs
	}
}

// injectableCAFromIndexer is an IndexerFunc indexing on certificates
// referenced by injectables.
func injectableCAFromIndexer(rawObj client.Object) []string {
	metaInfo, err := meta.Accessor(rawObj)
	if err != nil {
		return nil
	}

	// skip invalid certificate names
	certNameRaw := metaInfo.GetAnnotations()[cmapi.WantInjectAnnotation]
	if certNameRaw == "" {
		return nil
	}
	certName := splitNamespacedName(certNameRaw)
	if certName.Namespace == "" {
		return nil
	}

	return []string{certNameRaw}
}

// injectableCAFromSecretIndexer is an IndexerFunc indexing on secrets
// referenced by injectables.
func injectableCAFromSecretIndexer(rawObj client.Object) []string {
	metaInfo, err := meta.Accessor(rawObj)
	if err != nil {
		return nil
	}

	// skip invalid secret names
	secretNameRaw := metaInfo.GetAnnotations()[cmapi.WantInjectFromSecretAnnotation]
	if secretNameRaw == "" {
		return nil
	}
	secretName := splitNamespacedName(secretNameRaw)
	if secretName.Namespace == "" {
		return nil
	}

	return []string{secretNameRaw}
}

// hasInjectableAnnotation returns predicates that determine whether an object is a
// cainjector injectable by looking at whether it has one of the three
// annotations used to mark injectables.
func hasInjectableAnnotation(o client.Object) bool {
	annots := o.GetAnnotations()
	if _, ok := annots[cmapi.WantInjectAPIServerCAAnnotation]; ok {
		return true
	}
	if _, ok := annots[cmapi.WantInjectAnnotation]; ok {
		return true
	}
	if _, ok := annots[cmapi.WantInjectFromSecretAnnotation]; ok {
		return true
	}
	return false
}
