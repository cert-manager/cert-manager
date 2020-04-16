/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"k8s.io/apimachinery/pkg/labels"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/controller/expcertificates/internal/predicate"
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
