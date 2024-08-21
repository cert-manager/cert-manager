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

// UpdateCertificate will update the given Certificate's metrics for its expiry, renewal, and status
// condition.
func (m *Metrics) UpdateCertificate(crt *cmapi.Certificate) {
	m.updateCertificateStatus(crt)
	m.updateCertificateExpiry(crt)
	m.updateCertificateRenewalTime(crt)
}

// updateCertificateExpiry updates the expiry time of a certificate
func (m *Metrics) updateCertificateExpiry(crt *cmapi.Certificate) {
	expiryTime := 0.0

	if crt.Status.NotAfter != nil {
		expiryTime = float64(crt.Status.NotAfter.Unix())
	}

	m.certificateExpiryTimeSeconds.With(prometheus.Labels{
		"name":         crt.Name,
		"namespace":    crt.Namespace,
		"issuer_name":  crt.Spec.IssuerRef.Name,
		"issuer_kind":  crt.Spec.IssuerRef.Kind,
		"issuer_group": crt.Spec.IssuerRef.Group}).Set(expiryTime)
}

// updateCertificateRenewalTime updates the renew before duration of a certificate
func (m *Metrics) updateCertificateRenewalTime(crt *cmapi.Certificate) {
	renewalTime := 0.0

	if crt.Status.RenewalTime != nil {
		renewalTime = float64(crt.Status.RenewalTime.Unix())
	}

	m.certificateRenewalTimeSeconds.With(prometheus.Labels{
		"name":         crt.Name,
		"namespace":    crt.Namespace,
		"issuer_name":  crt.Spec.IssuerRef.Name,
		"issuer_kind":  crt.Spec.IssuerRef.Kind,
		"issuer_group": crt.Spec.IssuerRef.Group}).Set(renewalTime)

}

// updateCertificateStatus will update the metric for that Certificate
func (m *Metrics) updateCertificateStatus(crt *cmapi.Certificate) {
	for _, c := range crt.Status.Conditions {
		if c.Type == cmapi.CertificateConditionReady {
			m.updateCertificateReadyStatus(crt, c.Status)
			return
		}
	}

	// If no status condition set yet, set to Unknown
	m.updateCertificateReadyStatus(crt, cmmeta.ConditionUnknown)
}

func (m *Metrics) updateCertificateReadyStatus(crt *cmapi.Certificate, current cmmeta.ConditionStatus) {
	for _, condition := range readyConditionStatuses {
		value := 0.0

		if current == condition {
			value = 1.0
		}

		m.certificateReadyStatus.With(prometheus.Labels{
			"name":         crt.Name,
			"namespace":    crt.Namespace,
			"condition":    string(condition),
			"issuer_name":  crt.Spec.IssuerRef.Name,
			"issuer_kind":  crt.Spec.IssuerRef.Kind,
			"issuer_group": crt.Spec.IssuerRef.Group,
		}).Set(value)
	}
}

// RemoveCertificate will delete the Certificate metrics from continuing to be
// exposed.
func (m *Metrics) RemoveCertificate(key types.NamespacedName) {
	namespace, name := key.Namespace, key.Name

	m.certificateExpiryTimeSeconds.DeletePartialMatch(prometheus.Labels{"name": name, "namespace": namespace})
	m.certificateRenewalTimeSeconds.DeletePartialMatch(prometheus.Labels{"name": name, "namespace": namespace})
	m.certificateReadyStatus.DeletePartialMatch(prometheus.Labels{"name": name, "namespace": namespace})
}
