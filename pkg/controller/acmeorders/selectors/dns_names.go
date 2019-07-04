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

package selectors

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func DNSNames(sel cmapi.CertificateDNSNameSelector) Selector {
	return &dnsNamesSelector{
		allowedDNSNames: sel.DNSNames,
	}
}

type dnsNamesSelector struct {
	allowedDNSNames []string
}

func (s *dnsNamesSelector) Matches(meta metav1.ObjectMeta, dnsName string) (bool, int) {
	if len(s.allowedDNSNames) == 0 {
		return true, 0
	}

	for _, d := range s.allowedDNSNames {
		if dnsName == d {
			return true, 1
		}
	}

	return false, 0
}
