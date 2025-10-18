/*
Copyright 2025 The cert-manager Authors.

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

package collectors

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/labels"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
)

var (
	clusterIssuerReadyConditionStatuses = [...]cmmeta.ConditionStatus{cmmeta.ConditionTrue, cmmeta.ConditionFalse, cmmeta.ConditionUnknown}
	clusterIssuerReadyStatusMetric      = prometheus.NewDesc("certmanager_clusterissuer_ready_status", "The ready status of the ClusterIssuer.", []string{"name", "condition"}, nil)
)

type ClusterIssuerCollector struct {
	clusterIssuersLister           cmlisters.ClusterIssuerLister
	clusterIssuerReadyStatusMetric *prometheus.Desc
}

func NewClusterIssuerCollector(clusterIssuersLister cmlisters.ClusterIssuerLister) prometheus.Collector {
	return &ClusterIssuerCollector{
		clusterIssuersLister:           clusterIssuersLister,
		clusterIssuerReadyStatusMetric: clusterIssuerReadyStatusMetric,
	}
}

func (ic *ClusterIssuerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- ic.clusterIssuerReadyStatusMetric
}

func (ic *ClusterIssuerCollector) Collect(ch chan<- prometheus.Metric) {
	clusterIssuersList, err := ic.clusterIssuersLister.List(labels.Everything())
	if err != nil {
		return
	}

	for _, clusterissuer := range clusterIssuersList {
		ic.updateClusterIssuerReadyStatus(clusterissuer, ch)
	}
}

func (ic *ClusterIssuerCollector) updateClusterIssuerReadyStatus(clusterissuer *cmapi.ClusterIssuer, ch chan<- prometheus.Metric) {
	setMetric := func(clusterissuer *cmapi.ClusterIssuer, ch chan<- prometheus.Metric, status cmmeta.ConditionStatus) {
		for _, condition := range clusterIssuerReadyConditionStatuses {
			value := 0.0

			if status == condition {
				value = 1.0
			}

			metric := prometheus.MustNewConstMetric(
				ic.clusterIssuerReadyStatusMetric, prometheus.GaugeValue,
				value,
				clusterissuer.Name,
				string(condition),
			)

			ch <- metric
		}
	}

	for _, st := range clusterissuer.Status.Conditions {
		if st.Type == cmapi.IssuerConditionReady {
			setMetric(clusterissuer, ch, st.Status)
			return
		}
	}
	setMetric(clusterissuer, ch, cmmeta.ConditionUnknown)
}
