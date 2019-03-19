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

	"github.com/go-logr/logr"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

// setup for indexers used to trigger reconciliation on injected CA data.

var (
	// injectFromPath is the index key used to look up the value of inject-ca-from on targeted objects
	injectFromPath = ".metadata.annotations.inject-ca-from"

	// certmanagerAPIVersion is the APIVersion of the certmanager types,
	// pre-rendered to a string for quick comparison with an APIVersion field.
	certmanagerAPIVersion = certmanager.SchemeGroupVersion.String()
	// corev1APIVersion is the APIVersion of the core v1 Kubernetes types,
	// pre-rendered to a string for quick comparison with an APIVersion field.
	corev1APIVersion = corev1.SchemeGroupVersion.String()
)

// toInjectableFunc converts a given certificate to the reconcile requests for the corresponding injectables
// (webhooks, api services, etc) that reference it.
type toInjectableFunc func(log logr.Logger, cl client.Client, certName types.NamespacedName) []ctrl.Request

// certToInjectableFunc creates a toInjectableFunc that maps from certificates to the given type of injectable.
func certToInjectableFunc(listTyp runtime.Object, resourceName string) toInjectableFunc {
	return func(log logr.Logger, cl client.Client, certName types.NamespacedName) []ctrl.Request {
		log = log.WithValues("type", resourceName)
		objs := listTyp.DeepCopyObject()
		if err := cl.List(context.Background(), objs, client.MatchingField(injectFromPath, certName.String())); err != nil {
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

// secretMapper is a Mapper that converts secrets up to injectables, through certificates.
type secretMapper struct {
	client.Client
	log          logr.Logger
	toInjectable toInjectableFunc
}

func (m *secretMapper) InjectClient(c client.Client) error {
	m.Client = c
	return nil
}
func (m *secretMapper) Map(obj handler.MapObject) []ctrl.Request {
	// grab the certificate, if it exists
	certName := OwningCertForSecret(obj.Object.(*corev1.Secret))
	if certName == nil {
		return nil
	}

	secretName := types.NamespacedName{Name: obj.Meta.GetName(), Namespace: obj.Meta.GetNamespace()}
	log := m.log.WithValues("secret", secretName, "certificate", *certName)

	var cert certmanager.Certificate
	// confirm that a service owns this cert
	if err := m.Client.Get(context.Background(), *certName, &cert); err != nil {
		// TODO(directxman12): check for not found error?
		log.Error(err, "unable to fetch certificate that owns the secret")
		return nil
	}

	return m.toInjectable(log, m.Client, *certName)
}

// certMapper is a mapper that converts Certificates up to injectables, through services.
type certMapper struct {
	client.Client
	log          logr.Logger
	toInjectable toInjectableFunc
}

func (m *certMapper) InjectClient(c client.Client) error {
	m.Client = c
	return nil
}
func (m *certMapper) Map(obj handler.MapObject) []ctrl.Request {
	certName := types.NamespacedName{Name: obj.Meta.GetName(), Namespace: obj.Meta.GetNamespace()}
	log := m.log.WithValues("certificate", certName)
	return m.toInjectable(log, m.Client, certName)
}

// injectableIndexer makes a new IndexerFunc indexing on certificates referenced by injectables.
func injectableIndexer(rawObj runtime.Object) []string {
	metaInfo, err := meta.Accessor(rawObj)
	if err != nil {
		return nil
	}

	// skip invalid certificate names
	certNameRaw := metaInfo.GetAnnotations()[WantInjectAnnotation]
	if certNameRaw == "" {
		return nil
	}
	certName := splitNamespacedName(certNameRaw)
	if certName.Namespace == "" {
		return nil
	}

	return []string{certNameRaw}
}
