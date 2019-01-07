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

// Package metrics contains global structures related to metrics collection
// cert-manager exposes the following metrics:
// certificate_expiration_timestamp_seconds{name, namespace}
package metrics

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
)

const (
	// Namespace is the namespace for cert-manager metric names
	namespace                              = "certmanager"
	prometheusMetricsServerAddress         = "0.0.0.0:9402"
	prometheusMetricsServerShutdownTimeout = 5 * time.Second
	prometheusMetricsServerReadTimeout     = 8 * time.Second
	prometheusMetricsServerWriteTimeout    = 8 * time.Second
	prometheusMetricsServerMaxHeaderBytes  = 1 << 20 // 1 MiB
)

// Default set of metrics
var Default = New()

var CertificateExpiryTimeSeconds = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "certificate_expiration_timestamp_seconds",
		Help:      "The date after which the certificate expires. Expressed as a Unix Epoch Time.",
	},
	[]string{"name", "namespace"},
)

type Metrics struct {
	http.Server

	// TODO (@dippynark): switch this to use an interface to make it testable
	registry                     *prometheus.Registry
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
		registry:                     prometheus.NewRegistry(),
		CertificateExpiryTimeSeconds: CertificateExpiryTimeSeconds,
	}

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

	m.registry.MustRegister(m.CertificateExpiryTimeSeconds)

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

// UpdateCertificateExpiry updates the expiry time of a certificate
func (m *Metrics) UpdateCertificateExpiry(crt *v1alpha1.Certificate, secretLister corelisters.SecretLister) {

	// grab existing certificate
	cert, err := kube.SecretTLSCert(secretLister, crt.Namespace, crt.Spec.SecretName)
	if err != nil {
		if !apierrors.IsNotFound(err) && !errors.IsInvalidData(err) {
			runtime.HandleError(fmt.Errorf("[%s/%s] Error getting certificate '%s': %s", crt.Namespace, crt.Name, crt.Spec.SecretName, err.Error()))
		}
		return
	}

	updateX509Expiry(crt.Name, crt.Namespace, cert)
}

func updateX509Expiry(name, namespace string, cert *x509.Certificate) {
	// set certificate expiry time
	expiryTime := cert.NotAfter
	CertificateExpiryTimeSeconds.With(prometheus.Labels{
		"name":      name,
		"namespace": namespace}).Set(float64(expiryTime.Unix()))
}
