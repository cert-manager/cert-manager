/*
Copyright 2021 The cert-manager Authors.

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

package webhook

import (
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cert-manager/cert-manager/cmd/webhook/app/options"
	acmeinstall "github.com/cert-manager/cert-manager/internal/apis/acme/install"
	cminstall "github.com/cert-manager/cert-manager/internal/apis/certmanager/install"
	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
	metainstall "github.com/cert-manager/cert-manager/internal/apis/meta/install"
	"github.com/cert-manager/cert-manager/internal/plugin"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission/initializer"
	"github.com/cert-manager/cert-manager/pkg/webhook/authority"
	"github.com/cert-manager/cert-manager/pkg/webhook/handlers"
	"github.com/cert-manager/cert-manager/pkg/webhook/server"
	"github.com/cert-manager/cert-manager/pkg/webhook/server/tls"
)

var conversionHook handlers.ConversionHook = handlers.NewSchemeBackedConverter(logf.Log, Scheme)

// WithConversionHandler allows you to override the handler for the `/convert`
// endpoint in tests.
func WithConversionHandler(handler handlers.ConversionHook) func(*server.Server) {
	return func(s *server.Server) {
		s.ConversionWebhook = handler
	}
}

// NewCertManagerWebhookServer creates a new webhook server configured with all cert-manager
// resource types, validation, defaulting and conversion functions.
func NewCertManagerWebhookServer(log logr.Logger, _ options.WebhookFlags, opts config.WebhookConfiguration, optionFunctions ...func(*server.Server)) (*server.Server, error) {
	restcfg, err := clientcmd.BuildConfigFromFlags(opts.APIServerHost, opts.KubeConfig)
	if err != nil {
		return nil, err
	}

	cl, err := kubernetes.NewForConfig(restcfg)
	if err != nil {
		return nil, fmt.Errorf("error creating kubernetes client: %s", err)
	}

	// Set up the admission chain
	admissionHandler, err := buildAdmissionChain(cl)
	if err != nil {
		return nil, err
	}

	s := &server.Server{
		ListenAddr:        fmt.Sprintf(":%d", *opts.SecurePort),
		HealthzAddr:       fmt.Sprintf(":%d", *opts.HealthzPort),
		EnablePprof:       opts.EnablePprof,
		PprofAddr:         opts.PprofAddress,
		CertificateSource: buildCertificateSource(log, opts.TLSConfig, restcfg),
		CipherSuites:      opts.TLSConfig.CipherSuites,
		MinTLSVersion:     opts.TLSConfig.MinTLSVersion,
		ValidationWebhook: admissionHandler,
		MutationWebhook:   admissionHandler,
		ConversionWebhook: conversionHook,
	}
	for _, fn := range optionFunctions {
		fn(s)
	}
	return s, nil
}

func buildAdmissionChain(client kubernetes.Interface) (*admission.RequestHandler, error) {
	// Set up the admission chain
	pluginHandler := admission.NewPlugins(Scheme)
	plugin.RegisterAllPlugins(pluginHandler)
	authorizer, err := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: client.AuthorizationV1(),
		// cache responses for 1 second
		AllowCacheTTL: time.Second,
		DenyCacheTTL:  time.Second,
		WebhookRetryBackoff: &wait.Backoff{
			Duration: time.Second,
			Factor:   2,
			Jitter:   0.2,
			Steps:    2,
			Cap:      time.Second * 5,
		},
	}.New()
	if err != nil {
		return nil, fmt.Errorf("error creating authorization handler: %v", err)
	}
	pluginInitializer := initializer.New(client, nil, authorizer, nil)
	pluginChain, err := pluginHandler.NewFromPlugins(plugin.DefaultOnAdmissionPlugins().List(), pluginInitializer)
	if err != nil {
		return nil, fmt.Errorf("error building admission chain: %v", err)
	}
	return admission.NewRequestHandler(Scheme, pluginChain.(admission.ValidationInterface), pluginChain.(admission.MutationInterface)), nil
}

func buildCertificateSource(log logr.Logger, tlsConfig config.TLSConfig, restCfg *rest.Config) tls.CertificateSource {
	switch {
	case tlsConfig.FilesystemConfigProvided():
		log.V(logf.InfoLevel).Info("using TLS certificate from local filesystem", "private_key_path", tlsConfig.Filesystem.KeyFile, "certificate", tlsConfig.Filesystem.CertFile)
		return &tls.FileCertificateSource{
			CertPath: tlsConfig.Filesystem.CertFile,
			KeyPath:  tlsConfig.Filesystem.KeyFile,
		}
	case tlsConfig.DynamicConfigProvided():
		log.V(logf.InfoLevel).Info("using dynamic certificate generating using CA stored in Secret resource", "secret_namespace", tlsConfig.Dynamic.SecretNamespace, "secret_name", tlsConfig.Dynamic.SecretName)
		return &tls.DynamicSource{
			DNSNames: tlsConfig.Dynamic.DNSNames,
			Authority: &authority.DynamicAuthority{
				SecretNamespace: tlsConfig.Dynamic.SecretNamespace,
				SecretName:      tlsConfig.Dynamic.SecretName,
				RESTConfig:      restCfg,
			},
		}
	default:
		log.V(logf.WarnLevel).Info("serving insecurely as tls certificate data not provided")
	}
	return nil
}

func init() {
	cminstall.Install(Scheme)
	acmeinstall.Install(Scheme)
	metainstall.Install(Scheme)
}
