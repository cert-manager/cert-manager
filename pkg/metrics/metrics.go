/*
Copyright 2020 The Jetstack cert-manager contributors.

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
// certificate_ready_status{name, namespace, condition}
// acme_client_request_count{"scheme", "host", "path", "method", "status"}
// acme_client_request_duration_seconds{"scheme", "host", "path", "method", "status"}
// controller_sync_call_count{"controller"}
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

const (
	// Namespace is the namespace for cert-manager metric names
	namespace                              = "certmanager"
	prometheusMetricsServerShutdownTimeout = 5 * time.Second
	prometheusMetricsServerReadTimeout     = 8 * time.Second
	prometheusMetricsServerWriteTimeout    = 8 * time.Second
	prometheusMetricsServerMaxHeaderBytes  = 1 << 20 // 1 MiB
)

// Metrics is designed to be a shared object for updating the metrics exposed
// by cert-manager
type Metrics struct {
	log      logr.Logger
	registry *prometheus.Registry
	server   *http.Server

	certificateExpiryTimeSeconds     *prometheus.GaugeVec
	certificateReadyStatus           *prometheus.GaugeVec
	acmeClientRequestDurationSeconds *prometheus.SummaryVec
	acmeClientRequestCount           *prometheus.CounterVec
	controllerSyncCallCount          *prometheus.CounterVec
}

var readyConditionStatuses = [...]cmmeta.ConditionStatus{cmmeta.ConditionTrue, cmmeta.ConditionFalse, cmmeta.ConditionUnknown}

func New(log logr.Logger, listenAddress string) *Metrics {
	var (
		certificateExpiryTimeSeconds = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "certificate_expiration_timestamp_seconds",
				Help:      "The date after which the certificate expires. Expressed as a Unix Epoch Time.",
			},
			[]string{"name", "namespace"},
		)

		certificateReadyStatus = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "certificate_ready_status",
				Help:      "The ready status of the certificate.",
			},
			[]string{"name", "namespace", "condition"},
		)

		// acmeClientRequestCount is a Prometheus summary to collect the number of
		// requests made to each endpoint with the ACME client.
		acmeClientRequestCount = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "acme_client_request_count",
				Help:      "The number of requests made by the ACME client.",
				Subsystem: "http",
			},
			[]string{"scheme", "host", "path", "method", "status"},
		)

		// acmeClientRequestDurationSeconds is a Prometheus summary to collect request
		// times for the ACME client.
		acmeClientRequestDurationSeconds = prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace:  namespace,
				Name:       "acme_client_request_duration_seconds",
				Help:       "The HTTP request latencies in seconds for the ACME client.",
				Subsystem:  "http",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			},
			[]string{"scheme", "host", "path", "method", "status"},
		)

		controllerSyncCallCount = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "controller_sync_call_count",
				Help:      "The number of sync() calls made by a controller.",
			},
			[]string{"controller"},
		)
	)

	router := mux.NewRouter()

	// Create server and register Prometheus metrics handler
	m := &Metrics{
		log:      log.WithName("metrics"),
		registry: prometheus.NewRegistry(),
		server: &http.Server{
			Addr:           listenAddress,
			ReadTimeout:    prometheusMetricsServerReadTimeout,
			WriteTimeout:   prometheusMetricsServerWriteTimeout,
			MaxHeaderBytes: prometheusMetricsServerMaxHeaderBytes,
			Handler:        router,
		},

		certificateExpiryTimeSeconds:     certificateExpiryTimeSeconds,
		certificateReadyStatus:           certificateReadyStatus,
		acmeClientRequestCount:           acmeClientRequestCount,
		acmeClientRequestDurationSeconds: acmeClientRequestDurationSeconds,
		controllerSyncCallCount:          controllerSyncCallCount,
	}

	router.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))

	return m
}

// Start will register the Prometheu metrics, and start the Prometheus server
func (m *Metrics) Start(stopCh <-chan struct{}) {
	m.registry.MustRegister(m.certificateExpiryTimeSeconds)
	m.registry.MustRegister(m.certificateReadyStatus)
	m.registry.MustRegister(m.acmeClientRequestDurationSeconds)
	m.registry.MustRegister(m.acmeClientRequestCount)
	m.registry.MustRegister(m.controllerSyncCallCount)

	go func() {
		log := m.log.WithValues("address", m.server.Addr)
		log.Info("listening for connections on")
		if err := m.server.ListenAndServe(); err != nil {
			log.Error(err, "error running prometheus metrics server")
			return
		}

		log.Info("prometheus metrics server exited")
	}()

	<-stopCh
	m.shutdown()
}

// IncrementSyncCallCount will increase the sync counter for that controller.
func (m *Metrics) IncrementSyncCallCount(controllerName string) {
	m.controllerSyncCallCount.WithLabelValues(controllerName).Inc()
}

func (m *Metrics) shutdown() {
	m.log.Info("stopping Prometheus metrics server...")

	ctx, cancel := context.WithTimeout(context.Background(), prometheusMetricsServerShutdownTimeout)
	defer cancel()

	if err := m.server.Shutdown(ctx); err != nil {
		m.log.Error(err, "prometheus metrics server shutdown failed", err)
		return
	}

	m.log.Info("prometheus metrics server gracefully stopped")
}
