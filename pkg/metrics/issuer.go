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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/types"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// UpdateIssuer will update the given Issuer metrics for its expiry, renewal, and status
// condition.
func (m *Metrics) UpdateIssuer(iss *cmapi.Issuer) {
	m.UpdateIssuerStatus(iss)
}

// UpdateIssuerStatus will update the metric for that Issuer
func (m *Metrics) UpdateIssuerStatus(iss *cmapi.Issuer) {
	for _, c := range iss.Status.Conditions {
		if c.Type == cmapi.IssuerConditionReady {
			m.UpdateIssuerReadyStatus(iss, c.Status)
			return
		}
	}

	// If no status condition set yet, set to Unknown
	m.UpdateIssuerReadyStatus(iss, cmmeta.ConditionUnknown)
}

func (m *Metrics) UpdateIssuerReadyStatus(iss *cmapi.Issuer, current cmmeta.ConditionStatus) {
	for _, condition := range readyConditionStatuses {
		value := 0.0

		if current == condition {
			value = 1.0
		}

		m.issuerReadyStatus.With(prometheus.Labels{
			"name":      iss.Name,
			"namespace": iss.Namespace,
			"condition": string(condition),
		}).Set(value)
	}
}

// RemoveIssuer will delete the Issuer metrics from continuing to be
// exposed.
func (m *Metrics) RemoveIssuer(key types.NamespacedName) {
	namespace, name := key.Namespace, key.Name

	m.issuerReadyStatus.DeletePartialMatch(prometheus.Labels{"name": name, "namespace": namespace})
}
