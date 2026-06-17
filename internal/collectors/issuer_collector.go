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
	issuerReadyConditionStatuses = [...]cmmeta.ConditionStatus{cmmeta.ConditionTrue, cmmeta.ConditionFalse, cmmeta.ConditionUnknown}
	issuerReadyStatusMetric      = prometheus.NewDesc("certmanager_issuer_ready_status", "The ready status of the Issuer.", []string{"name", "namespace", "condition"}, nil)
)

type IssuerCollector struct {
	issuersLister           cmlisters.IssuerLister
	issuerReadyStatusMetric *prometheus.Desc
}

func NewIssuerCollector(issuersLister cmlisters.IssuerLister) prometheus.Collector {
	return &IssuerCollector{
		issuersLister:           issuersLister,
		issuerReadyStatusMetric: issuerReadyStatusMetric,
	}
}

func (ic *IssuerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- ic.issuerReadyStatusMetric
}

func (ic *IssuerCollector) Collect(ch chan<- prometheus.Metric) {
	issuersList, err := ic.issuersLister.List(labels.Everything())
	if err != nil {
		return
	}

	for _, issuer := range issuersList {
		ic.updateIssuerReadyStatus(issuer, ch)
	}
}

func (ic *IssuerCollector) updateIssuerReadyStatus(issuer *cmapi.Issuer, ch chan<- prometheus.Metric) {
	setMetric := func(issuer *cmapi.Issuer, ch chan<- prometheus.Metric, status cmmeta.ConditionStatus) {
		for _, condition := range issuerReadyConditionStatuses {
			value := 0.0

			if status == condition {
				value = 1.0
			}

			metric := prometheus.MustNewConstMetric(
				ic.issuerReadyStatusMetric, prometheus.GaugeValue,
				value,
				issuer.Name,
				issuer.Namespace,
				string(condition),
			)

			ch <- metric
		}
	}

	for _, st := range issuer.Status.Conditions {
		if st.Type == cmapi.IssuerConditionReady {
			setMetric(issuer, ch, st.Status)
			return
		}
	}
	setMetric(issuer, ch, cmmeta.ConditionUnknown)
}
