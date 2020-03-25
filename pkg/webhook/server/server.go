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

package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	ciphers "k8s.io/component-base/cli/flag"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/jetstack/cert-manager/pkg/util/profiling"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers"
	servertls "github.com/jetstack/cert-manager/pkg/webhook/server/tls"
)

var (
	// defaultScheme is used to encode and decode the AdmissionReview and
	// ConversionReview resources submitted to the webhook server.
	// It is not used for performing validation, mutation or conversion.
	defaultScheme = runtime.NewScheme()
)

func init() {
	admissionv1beta1.AddToScheme(defaultScheme)
	apiextensionsv1beta1.AddToScheme(defaultScheme)

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
	)
}

type Server struct {
	// ListenAddr is the address the HTTP server should listen on
	// This must be specified.
	ListenAddr string

	// HealthzAddr is the address the healthz HTTP server should listen on
	// If not specified, the healthz endpoint will not be exposed.
	HealthzAddr string

	// EnablePprof controls whether net/http/pprof handlers are registered with
	// the HTTP listener.
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

	// Log is an optional logger to write informational and error messages to.
	// If not specified, no messages will be logged.
	Log logr.Logger

	// CipherSuites is a slice of TLS Cipher Suite names
	CipherSuites []string
}

func (s *Server) Run(stopCh <-chan struct{}) error {
	if s.Log == nil {
		s.Log = crlog.NullLogger{}
	}

	internalStopCh := make(chan struct{})
	// only close the internalStopCh if it hasn't already been closed
	shutdown := false
	defer func() {
		if !shutdown {
			close(internalStopCh)
		}
	}()

	var healthzChan <-chan error
	var certSourceChan <-chan error

	// if a HealthzAddr is provided, start the healthz listener
	if s.HealthzAddr != "" {
		l, err := net.Listen("tcp", s.HealthzAddr)
		if err != nil {
			return err
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", s.handleHealthz)
		mux.HandleFunc("/livez", s.handleLivez)
		s.Log.Info("listening for insecure healthz connections", "address", s.HealthzAddr)
		healthzChan = s.startServer(l, internalStopCh, mux)
	}

	// create a listener for actual webhook requests
	l, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return err
	}

	// wrap the listener with TLS if a CertificateSource is provided
	if s.CertificateSource != nil {
		s.Log.Info("listening for secure connections", "address", s.ListenAddr)
		certSourceChan = s.startCertificateSource(internalStopCh)
		cipherSuites, err := ciphers.TLSCipherSuites(s.CipherSuites)
		if err != nil {
			return err
		}
		l = tls.NewListener(l, &tls.Config{
			GetCertificate:           s.CertificateSource.GetCertificate,
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CipherSuites:             cipherSuites,
		})
	} else {
		s.Log.Info("listening for insecure connections", "address", s.ListenAddr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", s.handle(s.validate))
	mux.HandleFunc("/mutate", s.handle(s.mutate))
	mux.HandleFunc("/convert", s.handle(s.convert))
	if s.EnablePprof {
		profiling.Install(mux)
		s.Log.Info("registered pprof handlers")
	}
	listenerChan := s.startServer(l, internalStopCh, mux)

	if certSourceChan == nil {
		certSourceChan = blockingChan(internalStopCh)
	}
	if healthzChan == nil {
		healthzChan = blockingChan(internalStopCh)
	}

	select {
	case err = <-healthzChan:
	case err = <-certSourceChan:
	case err = <-listenerChan:
	case <-stopCh:
	}

	close(internalStopCh)
	shutdown = true

	s.Log.Info("waiting for server to shutdown")
	waitForAll(healthzChan, certSourceChan, listenerChan)
	s.Log.Info("server shutdown successfully")

	return err
}

func (s *Server) startServer(l net.Listener, stopCh <-chan struct{}, handle http.Handler) <-chan error {
	ch := make(chan error)
	go func() {
		defer close(ch)

		srv := &http.Server{
			Handler: handle,
		}
		select {
		case err := <-channelWrapper(func() error { return srv.Serve(l) }):
			ch <- err
		case <-stopCh:
			// allow a fixed 5s for graceful shutdown
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				s.Log.Error(err, "failed to gracefully shutdown http server")
				ch <- err
			}
			s.Log.Info("shutdown HTTP server gracefully")
		}
	}()
	return ch
}

func (s *Server) startCertificateSource(stopCh <-chan struct{}) <-chan error {
	fn := func() error {
		return s.CertificateSource.Run(stopCh)
	}
	return channelWrapper(fn)
}

func waitForAll(chs ...<-chan error) error {
	for _, ch := range chs {
		if err := <-ch; err != nil {
			return fmt.Errorf("error waiting for goroutine to exit: %w", err)
		}
	}
	return nil
}

func channelWrapper(fn func() error) <-chan error {
	ch := make(chan error)
	go func() {
		defer close(ch)
		ch <- fn()
	}()
	return ch
}

// blockingChan returns a 'no-op' error channel.
// When stopCh is closed, the error channel will also be closed.
func blockingChan(stopCh <-chan struct{}) <-chan error {
	ch := make(chan error)
	go func() {
		defer close(ch)
		<-stopCh
	}()
	return ch
}

func (s *Server) scheme() *runtime.Scheme {
	if s.Scheme == nil {
		return defaultScheme
	}
	return s.Scheme
}

func (s *Server) validate(obj runtime.Object) runtime.Object {
	review := obj.(*admissionv1beta1.AdmissionReview)
	resp := s.ValidationWebhook.Validate(review.Request)
	review.Response = resp
	return review
}

func (s *Server) mutate(obj runtime.Object) runtime.Object {
	review := obj.(*admissionv1beta1.AdmissionReview)
	resp := s.MutationWebhook.Mutate(review.Request)
	review.Response = resp
	return review
}

func (s *Server) convert(obj runtime.Object) runtime.Object {
	review := obj.(*apiextensionsv1beta1.ConversionReview)
	resp := s.ConversionWebhook.Convert(review.Request)
	review.Response = resp
	return review
}

func (s *Server) handle(inner func(runtime.Object) runtime.Object) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()

		data, err := ioutil.ReadAll(req.Body)
		if err != nil {
			s.Log.Error(err, "failed to read request body")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		codec := json.NewSerializerWithOptions(json.DefaultMetaFactory, s.scheme(), s.scheme(), json.SerializerOptions{
			Pretty: true,
		})
		codec.Decode(data, nil, nil)
		obj, _, err := codec.Decode(data, nil, nil)
		if err != nil {
			s.Log.Error(err, "failed to decode request body")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		result := inner(obj)
		if err := codec.Encode(result, w); err != nil {
			s.Log.Error(err, "failed to encode response body")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	if s.CertificateSource != nil && !s.CertificateSource.Healthy() {
		s.Log.Info("Health check failed as CertificateSource is unhealthy")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLivez(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	w.WriteHeader(http.StatusOK)
}
