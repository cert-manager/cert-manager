/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specissfic language governing permissions and
limitations under the License.
*/

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/types"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// UpdateClusterIssuer will update the given ClusterIssuer metrics for its expiry, renewal, and status
// condition.
func (m *Metrics) UpdateClusterIssuer(ciss *cmapi.ClusterIssuer) {
	m.UpdateClusterIssuerStatus(ciss)
}

// UpdateClusterIssuerStatus will update the metric for that ClusterIssuer
func (m *Metrics) UpdateClusterIssuerStatus(ciss *cmapi.ClusterIssuer) {
	for _, c := range ciss.Status.Conditions {
		if c.Type == cmapi.IssuerConditionReady {
			m.UpdateClusterIssuerReadyStatus(ciss, c.Status)
			return
		}
	}

	// If no status condition set yet, set to Unknown
	m.UpdateClusterIssuerReadyStatus(ciss, cmmeta.ConditionUnknown)
}

func (m *Metrics) UpdateClusterIssuerReadyStatus(ciss *cmapi.ClusterIssuer, current cmmeta.ConditionStatus) {
	for _, condition := range readyConditionStatuses {
		value := 0.0

		if current == condition {
			value = 1.0
		}

		m.clusterIssuerReadyStatus.With(prometheus.Labels{
			"name":      ciss.Name,
			"condition": string(condition),
		}).Set(value)
	}
}

// RemoveClusterIssuer will delete the ClusterIssuer metrics from continuing to be
// exposed.
func (m *Metrics) RemoveClusterIssuer(key types.NamespacedName) {
	name := key.Name
	m.clusterIssuerReadyStatus.DeletePartialMatch(prometheus.Labels{"name": name})
}
