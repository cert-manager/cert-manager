/*
Copyright 2014 The Kubernetes Authors.

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

// Package metrics contains global structures related to metrics collection
// cert-manager exposes the following metrics:
// certificate_requests{name, namespace, issuer_name, issuer_scope, issuer_type, operation, result}
// certificate_expiry_time_seconds{name, namespace}
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/util/runtime"
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/kube"
)

const (
	// Namespace is the namespace for cert-manager metric names
	Namespace                              = "certmanager"
	prometheusMetricsServerAddress         = "0.0.0.0:9402"
	prometheusMetricsServerShutdownTimeout = 5 * time.Second
	prometheusMetricsServerReadTimeout     = 8 * time.Second
	prometheusMetricsServerWriteTimeout    = 8 * time.Second
	prometheusMetricsServerMaxHeaderBytes  = 1 << 20
)

type Metrics struct {
	http.Server

	// TODO (@dippynark): switch this to use an interface to make it testable
	registry                     *prometheus.Registry
	CertificateRequests          *prometheus.CounterVec
	CertificateExpiryTimeSeconds *prometheus.GaugeVec
}

func New() *Metrics {

	router := mux.NewRouter()

	// Create server and register prometheus metrics handler
	s := &Metrics{
		Server: http.Server{
			Addr:           prometheusMetricsServerAddress,
			ReadTimeout:    prometheusMetricsServerReadTimeout,
			WriteTimeout:   prometheusMetricsServerWriteTimeout,
			MaxHeaderBytes: prometheusMetricsServerMaxHeaderBytes,
			Handler:        router,
		},
		registry: prometheus.NewRegistry(),
		CertificateRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "certificate_requests",
				Help:      "Number of certificate requests",
			},
			[]string{"name", "namespace", "issuer_name", "issuer_kind", "issuer_type", "operation", "result"},
		),
		CertificateExpiryTimeSeconds: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "certificate_expiry_time_seconds",
				Help:      "Number of seconds after January 1, 1970 UTC that the certificate will expire",
			},
			[]string{"name", "namespace"},
		),
	}

	s.registry.MustRegister(s.CertificateRequests)
	s.registry.MustRegister(s.CertificateExpiryTimeSeconds)

	router.Handle("/metrics", promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}))

	return s
}

func (m *Metrics) waitShutdown(stopCh <-chan struct{}) {
	<-stopCh
	glog.Info("Stopping Prometheus metrics server...")

	ctx, cancel := context.WithTimeout(context.Background(), prometheusMetricsServerShutdownTimeout)
	defer cancel()

	if err := m.Shutdown(ctx); err != nil {
		glog.Errorf("Prometheus metrics server shutdown error: %v", err)
		return
	}

	glog.Info("Prometheus metrics server gracefully stopped")
}

func (m *Metrics) Start(stopCh <-chan struct{}) {

	go func() {

		glog.Infof("Listening on http://%s", m.Addr)
		if err := m.ListenAndServe(); err != nil {
			glog.Errorf("Error running prometheus metrics server: %s", err.Error())
			return
		}

		glog.Infof("Prometheus metrics server exited")

	}()

	m.waitShutdown(stopCh)
}

// IncCertificateRequestCount increments the certificate request count
// for a particular type and result
func (m *Metrics) IncCertificateRequestCount(
	certificateName,
	certificateNamespace,
	issuerName,
	issuerKind,
	issuerType,
	operation,
	result string) {

	var realIssuerKind string
	switch issuerKind {
	case "", v1alpha1.IssuerKind:
		realIssuerKind = v1alpha1.IssuerKind
	case v1alpha1.ClusterIssuerKind:
		realIssuerKind = v1alpha1.ClusterIssuerKind
	default:
		glog.Info(fmt.Sprintf(`invalid value %q for certificate issuer kind. Must be empty, %q or %q`, issuerKind, v1alpha1.IssuerKind, v1alpha1.ClusterIssuerKind))
		return
	}

	m.CertificateRequests.With(prometheus.Labels{
		"name":        certificateName,
		"namespace":   certificateNamespace,
		"issuer_name": issuerName,
		"issuer_kind": realIssuerKind,
		"issuer_type": issuerType,
		"operation":   operation,
		"result":      result}).Inc()

}

// UpdateCertificateExpiry updates the expiry time of a certificate
func (m *Metrics) UpdateCertificateExpiry(crt *v1alpha1.Certificate, secretLister corelisters.SecretLister) {

	// grab existing certificate and validate private key
	cert, err := kube.SecretTLSCert(secretLister, crt.Namespace, crt.Spec.SecretName)
	if err != nil {
		runtime.HandleError(fmt.Errorf("[%s/%s] Error getting certificate '%s': %s", crt.Namespace, crt.Name, crt.Spec.SecretName, err.Error()))
		return
	}

	// set certificate expiry time
	expiryTime := cert.NotAfter
	if expiryTime.IsZero() {
		return
	}

	m.CertificateExpiryTimeSeconds.With(prometheus.Labels{
		"name":      crt.Name,
		"namespace": crt.Namespace}).Set(float64(expiryTime.Unix()))
}
