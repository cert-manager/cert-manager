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
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	apiextensionsinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	runtimeutil "k8s.io/apimachinery/pkg/util/runtime"
	ciphers "k8s.io/component-base/cli/flag"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"

	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/cmapichecker"
	"github.com/jetstack/cert-manager/pkg/util/profiling"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers"
	servertls "github.com/jetstack/cert-manager/pkg/webhook/server/tls"
	"github.com/jetstack/cert-manager/pkg/webhook/server/util"
)

var (
	// defaultScheme is used to encode and decode the AdmissionReview and
	// ConversionReview resources submitted to the webhook server.
	// It is not used for performing validation, mutation or conversion.
	defaultScheme = runtime.NewScheme()
)

func init() {
	apiextensionsinstall.Install(defaultScheme)

	runtimeutil.Must(admissionv1beta1.AddToScheme(defaultScheme))
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

	// CipherSuites is the list of allowed cipher suites for the server.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	CipherSuites []string

	// MinTLSVersion is the minimum TLS version supported.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	MinTLSVersion string

	// APIChecker is used to check that the cert-manager CRDs have been installed on the K8S API server and that the cert-manager webhooks
	APIChecker cmapichecker.Interface

	listener net.Listener
}

type handleFunc func(context.Context, runtime.Object) (runtime.Object, error)

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
		mux.HandleFunc("/startupz", s.handleStartupz)
		s.Log.V(logf.InfoLevel).Info("listening for insecure healthz connections", "address", s.HealthzAddr)
		healthzChan = s.startServer(l, internalStopCh, mux)
	}

	// create a listener for actual webhook requests
	l, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return err
	}
	s.listener = l

	// wrap the listener with TLS if a CertificateSource is provided
	if s.CertificateSource != nil {
		s.Log.V(logf.InfoLevel).Info("listening for secure connections", "address", s.ListenAddr)
		certSourceChan = s.startCertificateSource(internalStopCh)
		cipherSuites, err := ciphers.TLSCipherSuites(s.CipherSuites)
		if err != nil {
			return err
		}
		minVersion, err := ciphers.TLSVersion(s.MinTLSVersion)
		if err != nil {
			return err
		}
		l = tls.NewListener(l, &tls.Config{
			GetCertificate:           s.CertificateSource.GetCertificate,
			CipherSuites:             cipherSuites,
			MinVersion:               minVersion,
			PreferServerCipherSuites: true,
		})
	} else {
		s.Log.V(logf.InfoLevel).Info("listening for insecure connections", "address", s.ListenAddr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", s.handle(s.validate))
	mux.HandleFunc("/mutate", s.handle(s.mutate))
	mux.HandleFunc("/convert", s.handle(s.convert))
	if s.EnablePprof {
		profiling.Install(mux)
		s.Log.V(logf.InfoLevel).Info("registered pprof handlers")
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

	s.Log.V(logf.DebugLevel).Info("waiting for server to shutdown")
	waitForAll(healthzChan, certSourceChan, listenerChan)

	s.Log.V(logf.InfoLevel).Info("server shutdown successfully")

	return err
}

// Port returns the port number that the webhook listener is listening on
func (s *Server) Port() (int, error) {
	if s.listener == nil {
		return 0, errors.New("Run() must be called before Port()")
	}
	tcpAddr, ok := s.listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("unexpected listen address type (expected tcp)")
	}
	return tcpAddr.Port, nil
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
			s.Log.V(logf.DebugLevel).Info("shutdown HTTP server gracefully")
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

func (s *Server) validate(ctx context.Context, obj runtime.Object) (runtime.Object, error) {
	outputVersion := admissionv1.SchemeGroupVersion
	review, isV1 := obj.(*admissionv1.AdmissionReview)
	if !isV1 {
		outputVersion = admissionv1beta1.SchemeGroupVersion
		reviewv1beta1, isv1beta1 := obj.(*admissionv1beta1.AdmissionReview)
		if !isv1beta1 {
			return nil, errors.New("request is not of type apiextensions v1 or v1beta1")
		}
		review = &admissionv1.AdmissionReview{}
		util.Convert_v1beta1_AdmissionReview_To_admission_AdmissionReview(reviewv1beta1, review)
	}
	resp := s.ValidationWebhook.Validate(ctx, review.Request)
	review.Response = resp

	// reply v1
	if outputVersion.Version == admissionv1.SchemeGroupVersion.Version {
		return review, nil
	}

	// reply v1beta1
	reviewv1beta1 := &admissionv1beta1.AdmissionReview{}
	util.Convert_admission_AdmissionReview_To_v1beta1_AdmissionReview(review, reviewv1beta1)
	return reviewv1beta1, nil
}

func (s *Server) mutate(ctx context.Context, obj runtime.Object) (runtime.Object, error) {
	outputVersion := admissionv1.SchemeGroupVersion
	review, isV1 := obj.(*admissionv1.AdmissionReview)
	if !isV1 {
		outputVersion = admissionv1beta1.SchemeGroupVersion
		reviewv1beta1, isv1beta1 := obj.(*admissionv1beta1.AdmissionReview)
		if !isv1beta1 {
			return nil, errors.New("request is not of type apiextensions v1 or v1beta1")
		}
		review = &admissionv1.AdmissionReview{}
		util.Convert_v1beta1_AdmissionReview_To_admission_AdmissionReview(reviewv1beta1, review)
	}
	resp := s.MutationWebhook.Mutate(ctx, review.Request)
	review.Response = resp

	// reply v1
	if outputVersion.Version == admissionv1.SchemeGroupVersion.Version {
		return review, nil
	}

	// reply v1beta1
	reviewv1beta1 := &admissionv1beta1.AdmissionReview{}
	util.Convert_admission_AdmissionReview_To_v1beta1_AdmissionReview(review, reviewv1beta1)
	return reviewv1beta1, nil
}

func (s *Server) convert(_ context.Context, obj runtime.Object) (runtime.Object, error) {
	switch review := obj.(type) {
	case *apiextensionsv1.ConversionReview:
		if review.Request == nil {
			return nil, errors.New("review.request was nil")
		}
		review.Response = s.ConversionWebhook.ConvertV1(review.Request)
		return review, nil
	case *apiextensionsv1beta1.ConversionReview:
		if review.Request == nil {
			return nil, errors.New("review.request was nil")
		}
		review.Response = s.ConversionWebhook.ConvertV1Beta1(review.Request)
		return review, nil
	default:
		return nil, fmt.Errorf("unsupported conversion review type: %T", review)
	}
}

func (s *Server) handle(inner handleFunc) func(w http.ResponseWriter, req *http.Request) {
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
		obj, _, err := codec.Decode(data, nil, nil)
		if err != nil {
			s.Log.Error(err, "failed to decode request body")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		result, err := inner(req.Context(), obj)
		if err != nil {
			s.Log.Error(err, "failed to process webhook request")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
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
		s.Log.V(logf.WarnLevel).Info("Health check failed as CertificateSource is unhealthy")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStartupz(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	log := s.Log.WithName("startupz")
	if err := s.APIChecker.Check(req.Context()); err != nil {
		log.V(logf.DebugLevel).Info("Failure", "reason", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.V(logf.DebugLevel).Info("Success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLivez(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	w.WriteHeader(http.StatusOK)
}
