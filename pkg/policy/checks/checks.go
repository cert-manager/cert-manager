/*
Copyright 2021 The cert-manager Authors.

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

package checks

import (
	"fmt"
	"net"
	"net/url"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/policy/checks/wildcard"
)

// String will match a policy string against a given string value, using
// wildcard match.
func String(el *field.ErrorList, path *field.Path, policy *string, request string) {
	// Allow all
	if policy == nil {
		return
	}

	if !wildcard.Matchs(*policy, request) {
		*el = append(*el, field.Invalid(path, request, *policy))
	}
}

// Strings will match a policy string slice against a given string value, using
// wildcard contains.
func Strings(el *field.ErrorList, path *field.Path, policy *[]string, request string) {
	// Allow all
	if policy == nil {
		return
	}

	if !wildcard.Contains(*policy, request) {
		*el = append(*el, field.Invalid(path, request, fmt.Sprintf("%v", *policy)))
	}
}

// StringSlice will match a policy string slice against a given string slice
// value, using wildcard subset.
func StringSlice(el *field.ErrorList, path *field.Path, policy *[]string, request []string) {
	// Allow all
	if policy == nil {
		return
	}

	if !wildcard.Subset(*policy, request) {
		*el = append(*el, field.Invalid(path, request, fmt.Sprintf("%v", *policy)))
	}
}

// IPSlice will match a policy string slice against a given net.IP slice, using
// string slice on the string IPs.
func IPSlice(el *field.ErrorList, path *field.Path, policy *[]string, request []net.IP) {
	var ips []string
	for _, ip := range request {
		ips = append(ips, ip.String())
	}
	StringSlice(el, path, policy, ips)
}

// IPSlice will match a policy string slice against a given url.URL slice,
// using string slice on the string urls.
func URLSlice(el *field.ErrorList, path *field.Path, policy *[]string, request []*url.URL) {
	var urls []string
	for _, url := range request {
		urls = append(urls, url.String())
	}
	StringSlice(el, path, policy, urls)
}

// KeyUsageSlice will match a policy key usage string slice against a given key
// usage slice, using string slice on the string key usages.
func KeyUsageSlice(el *field.ErrorList, path *field.Path, policy *[]cmapi.KeyUsage, request []cmapi.KeyUsage) {
	if policy == nil {
		return
	}
	var policyS []string
	for _, p := range *policy {
		policyS = append(policyS, string(p))
	}
	var requestS []string
	for _, r := range request {
		requestS = append(requestS, string(r))
	}

	StringSlice(el, path, &policyS, requestS)
}

// ObjectReference will match a policy object reference slice against a given
// object reference, using wildcard matches for each field. A request must
// wildcard match a single policy slice element in its entirety.
func ObjectReference(el *field.ErrorList, path *field.Path, policy *[]cmmeta.ObjectReference, request cmmeta.ObjectReference) {
	// Allow all
	if policy == nil {
		return
	}

	var found bool
	for _, policyI := range *policy {
		if !wildcard.Matchs(policyI.Name, request.Name) {
			continue
		}
		if !wildcard.Matchs(policyI.Kind, request.Kind) {
			continue
		}
		if !wildcard.Matchs(policyI.Group, request.Group) {
			continue
		}
	}

	if !found {
		*el = append(*el, field.Invalid(path, request, fmt.Sprintf("%v", *policy)))
	}
}

// MinDuration will compare the policy duration being larger than the request.
func MinDuration(el *field.ErrorList, path *field.Path, policy *metav1.Duration, request *metav1.Duration) {
	// Allow all
	if policy == nil {
		return
	}

	if policy.Duration > request.Duration {
		*el = append(*el, field.Invalid(path, request, policy.String()))
	}
}

// MaxDuration will compare the request duration being larger than the policy.
func MaxDuration(el *field.ErrorList, path *field.Path, policy *metav1.Duration, request *metav1.Duration) {
	// Allow all
	if policy == nil {
		return
	}

	if request.Duration > policy.Duration {
		*el = append(*el, field.Invalid(path, request, policy.String()))
	}
}

// MinSize will compare the policy size being larger than the request.
func MinSize(el *field.ErrorList, path *field.Path, policy *int, request int) {
	// Allow all
	if policy == nil {
		return
	}

	if *policy > request {
		*el = append(*el, field.Invalid(path, request, fmt.Sprintf("%d", *policy)))
	}
}

// MaxSize will compare the request size being larger than the policy.
func MaxSize(el *field.ErrorList, path *field.Path, policy *int, request int) {
	// Allow all
	if policy == nil {
		return
	}

	if request > *policy {
		*el = append(*el, field.Invalid(path, request, fmt.Sprintf("%d", *policy)))
	}
}
