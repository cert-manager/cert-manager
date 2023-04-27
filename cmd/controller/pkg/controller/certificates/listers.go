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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
)

// ListCertificateRequestsMatchingPredicates will list CertificateRequest
// resources using the provided lister, optionally applying the given predicate
// functions to filter the CertificateRequest resources returned.
func ListCertificateRequestsMatchingPredicates(lister cmlisters.CertificateRequestNamespaceLister, selector labels.Selector, predicates ...predicate.Func) ([]*cmapi.CertificateRequest, error) {
	reqs, err := lister.List(selector)
	if err != nil {
		return nil, err
	}
	funcs := predicate.Funcs(predicates)
	out := make([]*cmapi.CertificateRequest, 0)
	for _, req := range reqs {
		if funcs.Evaluate(req) {
			out = append(out, req)
		}
	}

	return out, nil
}

// ListCertificatesMatchingPredicates will list Certificate resources using
// the provided lister, optionally applying the given predicate functions to
// filter the Certificate resources returned.
func ListCertificatesMatchingPredicates(lister cmlisters.CertificateNamespaceLister, selector labels.Selector, predicates ...predicate.Func) ([]*cmapi.Certificate, error) {
	reqs, err := lister.List(selector)
	if err != nil {
		return nil, err
	}
	funcs := predicate.Funcs(predicates)
	out := make([]*cmapi.Certificate, 0)
	for _, req := range reqs {
		if funcs.Evaluate(req) {
			out = append(out, req)
		}
	}

	return out, nil
}

// ListSecretsMatchingPredicates will list Secret resources using
// the provided lister, optionally applying the given predicate functions to
// filter the Secret resources returned.
func ListSecretsMatchingPredicates(lister corelisters.SecretNamespaceLister, selector labels.Selector, predicates ...predicate.Func) ([]*corev1.Secret, error) {
	reqs, err := lister.List(selector)
	if err != nil {
		return nil, err
	}
	funcs := predicate.Funcs(predicates)
	out := make([]*corev1.Secret, 0)
	for _, req := range reqs {
		if funcs.Evaluate(req) {
			out = append(out, req)
		}
	}

	return out, nil
}
