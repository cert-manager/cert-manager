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
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/tools/cache"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// UpdateCertificateRequest updates the metrics for the given CertificateRequest's status.
func (m *Metrics) UpdateCertificateRequest(ctx context.Context, cr *cmapi.CertificateRequest) {
	key, err := cache.MetaNamespaceKeyFunc(cr)
	if err != nil {
		log := logf.WithRelatedResource(m.log, cr)
		log.Error(err, "failed to get key from CertificateRequest object")
		return
	}
	m.updateCertificateRequestStatus(key, cr)
}

// updateCertificateRequestStatus will update the metric for that CertificateRequest
func (m *Metrics) updateCertificateRequestStatus(key string, cr *cmapi.CertificateRequest) {
	for _, c := range cr.Status.Conditions {
		// Assuming there's a ConditionReady similar to Certificate for CertificateRequest
		if c.Type == cmapi.CertificateRequestConditionReady {
			m.updateCertificateRequestReadyStatus(cr, c.Status)
			return
		}
	}

	// If no status condition set yet, set to Unknown
	m.updateCertificateRequestReadyStatus(cr, cmmeta.ConditionUnknown)
}

func (m *Metrics) updateCertificateRequestReadyStatus(cr *cmapi.CertificateRequest, current cmmeta.ConditionStatus) {
	for _, condition := range readyConditionStatuses {
		value := 0.0

		if current == condition {
			value = 1.0
		}

		m.certificateRequestStatus.With(prometheus.Labels{
			"name":         cr.Name,
			"namespace":    cr.Namespace,
			"condition":    string(condition),
			"issuer_name":  cr.Spec.IssuerRef.Name,
			"issuer_kind":  cr.Spec.IssuerRef.Kind,
			"issuer_group": cr.Spec.IssuerRef.Group,
		}).Set(value)
	}
}
