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
	certReadyConditionStatuses     = [...]cmmeta.ConditionStatus{cmmeta.ConditionTrue, cmmeta.ConditionFalse, cmmeta.ConditionUnknown}
	certReadyStatusMetric          = prometheus.NewDesc("certmanager_certificate_ready_status", "The ready status of the certificate.", []string{"name", "namespace", "condition", "issuer_name", "issuer_kind", "issuer_group"}, nil)
	certNotAfterTimeSecondMetric   = prometheus.NewDesc("certmanager_certificate_not_after_timestamp_seconds", "The timestamp after which the certificate is invalid, expressed as a Unix Epoch Time.", []string{"name", "namespace", "issuer_name", "issuer_kind", "issuer_group"}, nil)
	certNotBeforeTimeSecondMetric  = prometheus.NewDesc("certmanager_certificate_not_before_timestamp_seconds", "The timestamp before which the certificate is invalid, expressed as a Unix Epoch Time.", []string{"name", "namespace", "issuer_name", "issuer_kind", "issuer_group"}, nil)
	certExpirationTimestampSeconds = prometheus.NewDesc("certmanager_certificate_expiration_timestamp_seconds", "The timestamp after which the certificate expires, expressed in Unix Epoch Time.", []string{"name", "namespace", "issuer_name", "issuer_kind", "issuer_group"}, nil)
	certRenewalTimestampSeconds    = prometheus.NewDesc("certmanager_certificate_renewal_timestamp_seconds", "The timestamp after which the certificate should be renewed, expressed in Unix Epoch Time.", []string{"name", "namespace", "issuer_name", "issuer_kind", "issuer_group"}, nil)
)

type CertificateCollector struct {
	certificatesLister                    cmlisters.CertificateLister
	certificateReadyStatusMetric          *prometheus.Desc
	certificateNotAfterTimeSecondMetric   *prometheus.Desc
	certificateNotBeforeTimeSecondMetric  *prometheus.Desc
	certificateExpirationTimestampSeconds *prometheus.Desc
	certificateRenewalTimestampSeconds    *prometheus.Desc
}

func NewCertificateCollector(certificatesLister cmlisters.CertificateLister) prometheus.Collector {
	return &CertificateCollector{
		certificatesLister:                    certificatesLister,
		certificateReadyStatusMetric:          certReadyStatusMetric,
		certificateNotAfterTimeSecondMetric:   certNotAfterTimeSecondMetric,
		certificateNotBeforeTimeSecondMetric:  certNotBeforeTimeSecondMetric,
		certificateExpirationTimestampSeconds: certExpirationTimestampSeconds,
		certificateRenewalTimestampSeconds:    certRenewalTimestampSeconds,
	}
}

func (cc *CertificateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- cc.certificateReadyStatusMetric
	ch <- cc.certificateNotAfterTimeSecondMetric
	ch <- cc.certificateNotBeforeTimeSecondMetric
	ch <- cc.certificateExpirationTimestampSeconds
	ch <- cc.certificateRenewalTimestampSeconds
}

func (cc *CertificateCollector) Collect(ch chan<- prometheus.Metric) {
	certsList, err := cc.certificatesLister.List(labels.Everything())
	if err != nil {
		return
	}

	for _, cert := range certsList {
		cc.updateCertificateReadyStatus(cert, ch)
		cc.updateCertificateNotAfter(cert, ch)
		cc.updateCertificateNotBefore(cert, ch)
		cc.updateCertificateExpiry(cert, ch)
		cc.updateCertificateRenewalTime(cert, ch)
	}
}

func (cc *CertificateCollector) updateCertificateReadyStatus(cert *cmapi.Certificate, ch chan<- prometheus.Metric) {
	setMetric := func(cert *cmapi.Certificate, ch chan<- prometheus.Metric, status cmmeta.ConditionStatus) {
		for _, condition := range certReadyConditionStatuses {
			value := 0.0

			if status == condition {
				value = 1.0
			}

			metric := prometheus.MustNewConstMetric(
				cc.certificateReadyStatusMetric, prometheus.GaugeValue,
				value,
				cert.Name,
				cert.Namespace,
				string(condition),
				cert.Spec.IssuerRef.Name,
				cert.Spec.IssuerRef.Kind,
				cert.Spec.IssuerRef.Group,
			)

			ch <- metric
		}
	}

	for _, st := range cert.Status.Conditions {
		if st.Type == cmapi.CertificateConditionReady {
			setMetric(cert, ch, st.Status)
			return
		}
	}

	setMetric(cert, ch, cmmeta.ConditionUnknown)
}

func (cc *CertificateCollector) updateCertificateNotAfter(cert *cmapi.Certificate, ch chan<- prometheus.Metric) {
	notAfterTime := 0.0

	if cert.Status.NotAfter != nil {
		notAfterTime = float64(cert.Status.NotAfter.Unix())
	}

	metric := prometheus.MustNewConstMetric(
		cc.certificateNotAfterTimeSecondMetric,
		prometheus.GaugeValue,
		notAfterTime,
		cert.Name,
		cert.Namespace,
		cert.Spec.IssuerRef.Name,
		cert.Spec.IssuerRef.Kind,
		cert.Spec.IssuerRef.Group,
	)

	ch <- metric
}

func (cc *CertificateCollector) updateCertificateNotBefore(cert *cmapi.Certificate, ch chan<- prometheus.Metric) {
	notBeforeTime := 0.0

	if cert.Status.NotBefore != nil {
		notBeforeTime = float64(cert.Status.NotBefore.Unix())
	}

	metric := prometheus.MustNewConstMetric(
		cc.certificateNotBeforeTimeSecondMetric,
		prometheus.GaugeValue,
		notBeforeTime,
		cert.Name,
		cert.Namespace,
		cert.Spec.IssuerRef.Name,
		cert.Spec.IssuerRef.Kind,
		cert.Spec.IssuerRef.Group,
	)

	ch <- metric
}

func (cc *CertificateCollector) updateCertificateExpiry(cert *cmapi.Certificate, ch chan<- prometheus.Metric) {
	expiryTime := 0.0

	if cert.Status.NotAfter != nil {
		expiryTime = float64(cert.Status.NotAfter.Unix())
	}

	metric := prometheus.MustNewConstMetric(
		cc.certificateExpirationTimestampSeconds,
		prometheus.GaugeValue,
		expiryTime,
		cert.Name,
		cert.Namespace,
		cert.Spec.IssuerRef.Name,
		cert.Spec.IssuerRef.Kind,
		cert.Spec.IssuerRef.Group,
	)

	ch <- metric
}

func (cc *CertificateCollector) updateCertificateRenewalTime(cert *cmapi.Certificate, ch chan<- prometheus.Metric) {
	renewalTime := 0.0

	if cert.Status.RenewalTime != nil {
		renewalTime = float64(cert.Status.RenewalTime.Unix())
	}

	metric := prometheus.MustNewConstMetric(
		cc.certificateRenewalTimestampSeconds,
		prometheus.GaugeValue,
		renewalTime,
		cert.Name,
		cert.Namespace,
		cert.Spec.IssuerRef.Name,
		cert.Spec.IssuerRef.Kind,
		cert.Spec.IssuerRef.Group,
	)

	ch <- metric
}
