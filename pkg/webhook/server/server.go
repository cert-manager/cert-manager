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
	"io"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	admissionv1 "k8s.io/api/admission/v1"
	apiextensionsinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	runtimeutil "k8s.io/apimachinery/pkg/util/runtime"
	ciphers "k8s.io/component-base/cli/flag"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/profiling"
	"github.com/cert-manager/cert-manager/pkg/webhook/handlers"
	servertls "github.com/cert-manager/cert-manager/pkg/webhook/server/tls"
)

var (
	// defaultScheme is used to encode and decode the AdmissionReview and
	// ConversionReview resources submitted to the webhook server.
	// It is not used for performing validation, mutation or conversion.
	defaultScheme = runtime.NewScheme()

	ErrNotListening = errors.New("Server is not listening yet")
)

func init() {
	apiextensionsinstall.Install(defaultScheme)
	runtimeutil.Must(admissionv1.AddToScheme(defaultScheme))

	// we need to add the options to empty v1
	// TODO fix the server code to avoid this
	metav1.AddToGroupVersion(defaultScheme, schema.GroupVersion{Version: "v1"})

	// TODO: keep the generic API server from wanting this
	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	defaultScheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
		&metav1.CreateOptions{},
	)
}

type Server struct {
	// ListenAddr is the address the HTTP server should listen on
	// This must be specified.
	ListenAddr string

	// HealthzAddr is the address the healthz HTTP server should listen on
	// If not specified, the healthz endpoint will not be exposed.
	HealthzAddr string

	// PprofAddr is the address the pprof endpoint should be served on if enabled.
	PprofAddr string
	// EnablePprof determines whether pprof is enabled.
	EnablePprof bool

	// Scheme is used to decode/encode request/response payloads.
	// If not specified, a default scheme that registers the AdmissionReview
	// and ConversionReview resource types will be used.
	// It is not used for performing validation, mutation or conversion.
	Scheme *runtime.Scheme

	// If specified, the server will listen with TLS using certificates
	// provided by this CertificateSource.
	CertificateSource servertls.CertificateSource

	ValidationWebhook handlers.ValidatingAdmissionHook
	MutationWebhook   handlers.MutatingAdmissionHook
	ConversionWebhook handlers.ConversionHook

	log logr.Logger

	// CipherSuites is the list of allowed cipher suites for the server.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	CipherSuites []string

	// MinTLSVersion is the minimum TLS version supported.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	MinTLSVersion string

	listener net.Listener
}

type handleFunc func(context.Context, runtime.Object) (runtime.Object, error)

func (s *Server) Run(ctx context.Context) error {
	s.log = logf.FromContext(ctx)
	g, gctx := errgroup.WithContext(ctx)

	// if a HealthzAddr is provided, start the healthz listener
	if s.HealthzAddr != "" {
		healthzListener, err := net.Listen("tcp", s.HealthzAddr)
		if err != nil {
			return err
		}

		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/healthz", s.handleHealthz)
		healthMux.HandleFunc("/livez", s.handleLivez)
		s.log.V(logf.InfoLevel).Info("listening for insecure healthz connections", "address", s.HealthzAddr)
		server := &http.Server{
			Handler: healthMux,
		}
		g.Go(func() error {
			<-gctx.Done()
			// allow a timeout for graceful shutdown
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				return err
			}
			return nil
		})
		g.Go(func() error {
			if err := server.Serve(healthzListener); err != http.ErrServerClosed {
				return err
			}
			return nil
		})
	}

	// if a PprofAddr is provided, start the pprof listener
	if s.EnablePprof {
		pprofListener, err := net.Listen("tcp", s.PprofAddr)
		if err != nil {
			return err
		}

		profilerMux := http.NewServeMux()
		// Add pprof endpoints to this mux
		profiling.Install(profilerMux)
		s.log.V(logf.InfoLevel).Info("running go profiler on", "address", s.PprofAddr)
		server := &http.Server{
			Handler: profilerMux,
		}
		g.Go(func() error {
			<-gctx.Done()
			// allow a timeout for graceful shutdown
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				return err
			}
			return nil
		})
		g.Go(func() error {
			if err := server.Serve(pprofListener); err != http.ErrServerClosed {
				return err
			}
			return nil
		})
	}

	// create a listener for actual webhook requests
	listener, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return err
	}

	// wrap the listener with TLS if a CertificateSource is provided
	if s.CertificateSource != nil {
		s.log.V(logf.InfoLevel).Info("listening for secure connections", "address", s.ListenAddr)
		g.Go(func() error {
			if err := s.CertificateSource.Run(gctx); (err != nil) && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		})
		cipherSuites, err := ciphers.TLSCipherSuites(s.CipherSuites)
		if err != nil {
			return err
		}
		minVersion, err := ciphers.TLSVersion(s.MinTLSVersion)
		if err != nil {
			return err
		}
		listener = tls.NewListener(listener, &tls.Config{
			GetCertificate:           s.CertificateSource.GetCertificate,
			CipherSuites:             cipherSuites,
			MinVersion:               minVersion,
			PreferServerCipherSuites: true,
		})
	} else {
		s.log.V(logf.InfoLevel).Info("listening for insecure connections", "address", s.ListenAddr)
	}

	s.listener = listener
	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/validate", s.handle(s.validate))
	serverMux.HandleFunc("/mutate", s.handle(s.mutate))
	serverMux.HandleFunc("/convert", s.handle(s.convert))
	server := &http.Server{
		Handler: serverMux,
	}
	g.Go(func() error {
		<-gctx.Done()
		// allow a timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		if err := server.Serve(s.listener); err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	return g.Wait()
}

// Port returns the port number that the webhook listener is listening on
func (s *Server) Port() (int, error) {
	if s.listener == nil {
		return 0, ErrNotListening
	}
	tcpAddr, ok := s.listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("unexpected listen address type (expected tcp)")
	}
	return tcpAddr.Port, nil
}

func (s *Server) scheme() *runtime.Scheme {
	if s.Scheme == nil {
		return defaultScheme
	}
	return s.Scheme
}

func (s *Server) validate(ctx context.Context, obj runtime.Object) (runtime.Object, error) {
	review, isV1 := obj.(*admissionv1.AdmissionReview)
	if !isV1 {
		return nil, errors.New("request is not of type apiextensions v1")
	}
	review.Response = s.ValidationWebhook.Validate(ctx, review.Request)
	return review, nil
}

func (s *Server) mutate(ctx context.Context, obj runtime.Object) (runtime.Object, error) {
	review, isV1 := obj.(*admissionv1.AdmissionReview)
	if !isV1 {
		return nil, errors.New("request is not of type apiextensions v1")
	}
	review.Response = s.MutationWebhook.Mutate(ctx, review.Request)
	return review, nil
}

func (s *Server) convert(_ context.Context, obj runtime.Object) (runtime.Object, error) {
	switch review := obj.(type) {
	case *apiextensionsv1.ConversionReview:
		if review.Request == nil {
			return nil, errors.New("review.request was nil")
		}
		review.Response = s.ConversionWebhook.Convert(review.Request)
		return review, nil
	default:
		return nil, fmt.Errorf("unsupported conversion review type: %T", review)
	}
}

func (s *Server) handle(inner handleFunc) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()

		data, err := io.ReadAll(req.Body)
		if err != nil {
			s.log.Error(err, "failed to read request body")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		codec := json.NewSerializerWithOptions(json.DefaultMetaFactory, s.scheme(), s.scheme(), json.SerializerOptions{
			Pretty: true,
		})
		obj, _, err := codec.Decode(data, nil, nil)
		if err != nil {
			s.log.Error(err, "failed to decode request body")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		result, err := inner(req.Context(), obj)
		if err != nil {
			s.log.Error(err, "failed to process webhook request")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := codec.Encode(result, w); err != nil {
			s.log.Error(err, "failed to encode response body")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	if s.CertificateSource != nil && !s.CertificateSource.Healthy() {
		s.log.V(logf.WarnLevel).Info("Health check failed as CertificateSource is unhealthy")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLivez(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	w.WriteHeader(http.StatusOK)
}
