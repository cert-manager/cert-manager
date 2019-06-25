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

func Labels(sel cmapi.CertificateDNSNameSelector) Selector {
	return &labelSelector{
		requiredLabels: sel.MatchLabels,
	}
}

type labelSelector struct {
	requiredLabels map[string]string
}

func (s *labelSelector) Matches(meta metav1.ObjectMeta, dnsName string) (bool, int) {
	if len(s.requiredLabels) == 0 {
		return true, 0
	}

	hasAllLabels := true
	matches := 0
	for k, v := range s.requiredLabels {
		actualV, hasLabel := meta.Labels[k]
		if !hasLabel || v != actualV {
			hasAllLabels = false
			break
		}
		matches++
	}

	return hasAllLabels, matches
}
