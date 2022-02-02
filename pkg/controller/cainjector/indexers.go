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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// setup for indexers used to trigger reconciliation on injected CA data.

// certificateToInjectableFunc converts a given certificate to the reconcile requests for the corresponding injectables
// (webhooks, api services, etc) that reference it.
type certificateToInjectableFunc func(log logr.Logger, cl client.Reader, certName types.NamespacedName) []ctrl.Request

// buildCertToInjectableFunc creates a certificateToInjectableFunc that maps from certificates to the given type of injectable.
func buildCertToInjectableFunc(listTyp runtime.Object, resourceName string) certificateToInjectableFunc {
	return func(log logr.Logger, cl client.Reader, certName types.NamespacedName) []ctrl.Request {
		log = log.WithValues("type", resourceName)
		objs := listTyp.DeepCopyObject().(client.ObjectList)
		if err := cl.List(context.Background(), objs, client.MatchingFields{injectFromPath: certName.String()}); err != nil {
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

// secretForCertificateMapper is a Mapper that converts secrets up to injectables, through certificates.
type secretForCertificateMapper struct {
	Client                  client.Reader
	log                     logr.Logger
	certificateToInjectable certificateToInjectableFunc
}

func (m *secretForCertificateMapper) Map(obj client.Object) []ctrl.Request {
	// grab the certificate, if it exists
	certName := OwningCertForSecret(obj.(*corev1.Secret))
	if certName == nil {
		return nil
	}

	secretName := types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}
	log := m.log.WithValues("secret", secretName, "certificate", *certName)

	var cert cmapi.Certificate
	// confirm that a service owns this cert
	if err := m.Client.Get(context.Background(), *certName, &cert); err != nil {
		// TODO(directxman12): check for not found error?
		log.Error(err, "unable to fetch certificate that owns the secret")
		return nil
	}

	return m.certificateToInjectable(log, m.Client, *certName)
}

// certMapper is a mapper that converts Certificates up to injectables
type certMapper struct {
	Client       client.Reader
	log          logr.Logger
	toInjectable certificateToInjectableFunc
}

func (m *certMapper) Map(obj client.Object) []ctrl.Request {
	certName := types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}
	log := m.log.WithValues("certificate", certName)
	return m.toInjectable(log, m.Client, certName)
}

var (
	// injectFromPath is the index key used to look up the value of inject-ca-from on targeted objects
	injectFromPath = ".metadata.annotations.inject-ca-from"
)

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

// secretToInjectableFunc converts a given certificate to the reconcile requests for the corresponding injectables
// (webhooks, api services, etc) that reference it.
type secretToInjectableFunc func(log logr.Logger, cl client.Reader, certName types.NamespacedName) []ctrl.Request

// buildSecretToInjectableFunc creates a certificateToInjectableFunc that maps from certificates to the given type of injectable.
func buildSecretToInjectableFunc(listTyp runtime.Object, resourceName string) secretToInjectableFunc {
	return func(log logr.Logger, cl client.Reader, secretName types.NamespacedName) []ctrl.Request {
		log = log.WithValues("type", resourceName)
		objs := listTyp.DeepCopyObject().(client.ObjectList)
		if err := cl.List(context.Background(), objs, client.MatchingFields{injectFromSecretPath: secretName.String()}); err != nil {
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

// secretForInjectableMapper is a Mapper that converts secrets to injectables
// via the 'inject-ca-from-secret' annotation
type secretForInjectableMapper struct {
	Client             client.Reader
	log                logr.Logger
	secretToInjectable secretToInjectableFunc
}

func (m *secretForInjectableMapper) Map(obj client.Object) []ctrl.Request {
	secretName := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
	log := m.log.WithValues("secret", secretName)
	return m.secretToInjectable(log, m.Client, secretName)
}

var (
	// injectFromSecretPath is the index key used to look up the value of
	// inject-ca-from-secret on targeted objects
	injectFromSecretPath = ".metadata.annotations.inject-ca-from-secret"
)

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
