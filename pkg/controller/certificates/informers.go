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

package certificates

import (
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
)

// EnqueueCertificatesForResourceUsingPredicates will return a function
// that can be used as an OnAdd handler for a SharedIndexInformer.
// It should be used as a handler for resources that are referenced
// in some way by Certificates.
// The namespace of the object being processed will be used in the List
// call when enqueuing Certificate resources.
// If no predicate constructors are given, all Certificate resources will be
// enqueued on every invocation.
func EnqueueCertificatesForResourceUsingPredicates(log logr.Logger, queue workqueue.TypedInterface[types.NamespacedName], lister cmlisters.CertificateLister, selector labels.Selector, predicateBuilders ...predicate.ExtractorFunc) func(obj interface{}) {
	return func(obj interface{}) {
		s, ok := obj.(metav1.Object)
		if !ok {
			log.V(logf.ErrorLevel).Info("Non-Object type resource passed to EnqueueCertificatesForSecretUsingPredicates")
			return
		}

		// 'Construct' the predicate functions using the given Secret
		predicates := make(predicate.Funcs, len(predicateBuilders))
		for i, b := range predicateBuilders {
			predicates[i] = b(s.(runtime.Object))
		}

		certs, err := ListCertificatesMatchingPredicates(lister.Certificates(s.GetNamespace()), selector, predicates...)
		if err != nil {
			log.Error(err, "Failed listing Certificate resources")
			return
		}

		for _, cert := range certs {
			queue.Add(types.NamespacedName{
				Name:      cert.Name,
				Namespace: cert.Namespace,
			})
		}
	}
}
