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

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ciphers "k8s.io/component-base/cli/flag"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	servertls "github.com/cert-manager/cert-manager/pkg/server/tls"
	"github.com/cert-manager/cert-manager/pkg/util/profiling"
	cmadmission "github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

const (
	// This is intended to mitigate "slowloris" attacks by limiting the time a
	// deliberately slow client can spend sending HTTP headers.
	// This default value is copied from:
	// * kubernetes api-server:
	//   https://github.com/kubernetes/kubernetes/blob/9e028b40b9e970142191259effe796b3dab39828/staging/src/k8s.io/apiserver/pkg/server/secure_serving.go#L165-L173
	// * controller-runtime:
	//   https://github.com/kubernetes-sigs/controller-runtime/blob/1ea2be573f7887a9fbd766e9a921c5af344da6eb/pkg/internal/httpserver/server.go#L14
	defaultReadHeaderTimeout = 32 * time.Second
)

var (
	ErrNotListening = errors.New("Server is not listening yet")
)

type Server struct {
	// ListenAddr is the address the HTTP server should listen on
	// This must be specified.
	ListenAddr int

	// HealthzAddr is the address the healthz HTTP server should listen on
	// If not specified, the healthz endpoint will not be exposed.
	HealthzAddr *int

	// PprofAddress is the address the pprof endpoint should be served on if enabled.
	PprofAddress string
	// EnablePprof determines whether pprof is enabled.
	EnablePprof bool

	// ResourceScheme is used to decode resources and convert them to
	// internal types when validating.
	ResourceScheme *runtime.Scheme

	// If specified, the server will listen with TLS using certificates
	// provided by this CertificateSource.
	CertificateSource servertls.CertificateSource

	ValidationWebhook cmadmission.ValidationInterface
	MutationWebhook   cmadmission.MutationInterface

	// CipherSuites is the list of allowed cipher suites for the server.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	CipherSuites []string

	// MinTLSVersion is the minimum TLS version supported.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	MinTLSVersion string

	// The host and port that the metrics endpoint should listen on.
	MetricsListenAddress string

	// If specified, the metrics server will listen with TLS using certificates
	// provided by this CertificateSource.
	MetricsCertificateSource servertls.CertificateSource

	// MetricsCipherSuites is the list of allowed cipher suites for the server.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	MetricsCipherSuites []string

	// MetricsMinTLSVersion is the minimum TLS version supported.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	MetricsMinTLSVersion string
}

func (s *Server) Run(ctx context.Context) error {
	if s.CertificateSource == nil {
		return fmt.Errorf("no CertificateSource specified")
	}

	log := logf.FromContext(ctx)

	cipherSuites, err := ciphers.TLSCipherSuites(s.CipherSuites)
	if err != nil {
		return err
	}
	minVersion, err := ciphers.TLSVersion(s.MinTLSVersion)
	if err != nil {
		return err
	}

	metricsCipherSuites, err := ciphers.TLSCipherSuites(s.MetricsCipherSuites)
	if err != nil {
		return err
	}
	metricsMinVersion, err := ciphers.TLSVersion(s.MetricsMinTLSVersion)
	if err != nil {
		return err
	}

	if s.ListenAddr == 0 {
		webhookPort, err := freePort()
		if err != nil {
			return err
		}

		s.ListenAddr = webhookPort
	}

	mgr, err := ctrl.NewManager(
		&rest.Config{}, // controller-runtime does not need to talk to the API server
		ctrl.Options{
			Scheme:         s.ResourceScheme,
			Logger:         log,
			LeaderElection: false, // The webhook component does not need to perform leader election
			Metrics: metricsserver.Options{
				BindAddress:   s.MetricsListenAddress,
				SecureServing: s.MetricsCertificateSource != nil,
				TLSOpts: []func(*tls.Config){
					func(cfg *tls.Config) {
						cfg.CipherSuites = metricsCipherSuites
						cfg.MinVersion = metricsMinVersion
						cfg.GetCertificate = s.MetricsCertificateSource.GetCertificate
					},
				},
			},
			WebhookServer: webhook.NewServer(webhook.Options{
				Port: s.ListenAddr,
				TLSOpts: []func(*tls.Config){
					func(cfg *tls.Config) {
						cfg.CipherSuites = cipherSuites
						cfg.MinVersion = minVersion
						cfg.GetCertificate = s.CertificateSource.GetCertificate
					},
				},
			}),
		})
	if err != nil {
		return fmt.Errorf("error creating manager: %v", err)
	}

	if err := mgr.Add(s.CertificateSource); err != nil {
		return err
	}

	if s.MetricsCertificateSource != nil {
		if err := mgr.Add(s.MetricsCertificateSource); err != nil {
			return err
		}
	}

	// if a HealthzAddr is provided, start the healthz listener
	if s.HealthzAddr != nil {
		healthzListener, err := net.Listen("tcp", fmt.Sprintf(":%d", *s.HealthzAddr))
		if err != nil {
			return err
		}

		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/healthz", s.handleHealthz)
		healthMux.HandleFunc("/livez", s.handleLivez)
		log.V(logf.InfoLevel).Info("listening for insecure healthz connections", "address", s.HealthzAddr)
		server := &http.Server{
			Handler:           healthMux,
			ReadHeaderTimeout: defaultReadHeaderTimeout, // Mitigation for G112: Potential slowloris attack
		}

		if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			<-ctx.Done()

			// allow a timeout for graceful shutdown
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// nolint: contextcheck
			if err := server.Shutdown(shutdownCtx); err != nil {
				return err
			}
			return nil
		})); err != nil {
			return err
		}

		if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			if err := server.Serve(healthzListener); err != http.ErrServerClosed {
				return err
			}
			return nil
		})); err != nil {
			return err
		}
	}

	// if a PprofAddr is provided, start the pprof listener
	if s.EnablePprof {
		pprofListener, err := net.Listen("tcp", s.PprofAddress)
		if err != nil {
			return err
		}

		profilerMux := http.NewServeMux()
		// Add pprof endpoints to this mux
		profiling.Install(profilerMux)
		log.V(logf.InfoLevel).Info("running go profiler on", "address", s.PprofAddress)
		server := &http.Server{
			Handler:           profilerMux,
			ReadHeaderTimeout: defaultReadHeaderTimeout, // Mitigation for G112: Potential slowloris attack
		}

		if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			<-ctx.Done()

			// allow a timeout for graceful shutdown
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// nolint: contextcheck
			if err := server.Shutdown(shutdownCtx); err != nil {
				return err
			}
			return nil
		})); err != nil {
			return err
		}

		if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			if err := server.Serve(pprofListener); err != http.ErrServerClosed {
				return err
			}
			return nil
		})); err != nil {
			return err
		}
	}

	mgr.GetWebhookServer().Register("/mutate", cmadmission.NewCustomMutationWebhook(s.MutationWebhook))

	mgr.GetWebhookServer().Register("/validate", cmadmission.NewCustomValidationWebhook(mgr.GetScheme(), s.ValidationWebhook))

	return mgr.Start(ctx)
}

func freePort() (int, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		return -1, err
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}

// Port returns the port number that the webhook listener is listening on
func (s *Server) Port() (int, error) {
	if s.ListenAddr == 0 {
		return 0, ErrNotListening
	}

	return s.ListenAddr, nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	if s.CertificateSource != nil && !s.CertificateSource.Healthy() {
		logf.FromContext(req.Context()).V(logf.WarnLevel).Info("Health check failed as CertificateSource is unhealthy")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLivez(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	w.WriteHeader(http.StatusOK)
}
