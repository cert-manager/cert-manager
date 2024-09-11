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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"

	acmeinstall "github.com/cert-manager/cert-manager/internal/apis/acme/install"
	cminstall "github.com/cert-manager/cert-manager/internal/apis/certmanager/install"
	"github.com/cert-manager/cert-manager/internal/apis/config/shared"
	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
	metainstall "github.com/cert-manager/cert-manager/internal/apis/meta/install"
	crapproval "github.com/cert-manager/cert-manager/internal/webhook/admission/certificaterequest/approval"
	cridentity "github.com/cert-manager/cert-manager/internal/webhook/admission/certificaterequest/identity"
	"github.com/cert-manager/cert-manager/internal/webhook/admission/resourcevalidation"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/server/tls"
	"github.com/cert-manager/cert-manager/pkg/server/tls/authority"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
	"github.com/cert-manager/cert-manager/pkg/webhook/server"
)

// NewCertManagerWebhookServer creates a new webhook server configured with all cert-manager
// resource types, validation, defaulting and conversion functions.
func NewCertManagerWebhookServer(log logr.Logger, opts config.WebhookConfiguration, optionFunctions ...func(*server.Server)) (*server.Server, error) {
	crlog.SetLogger(log)

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

	scheme := runtime.NewScheme()
	cminstall.Install(scheme)
	acmeinstall.Install(scheme)
	metainstall.Install(scheme)

	s := &server.Server{
		ResourceScheme:           scheme,
		ListenAddr:               int(opts.SecurePort),
		HealthzAddr:              ptr.To(int(opts.HealthzPort)),
		EnablePprof:              opts.EnablePprof,
		PprofAddress:             opts.PprofAddress,
		CertificateSource:        buildCertificateSource(log, opts.TLSConfig, restcfg),
		CipherSuites:             opts.TLSConfig.CipherSuites,
		MinTLSVersion:            opts.TLSConfig.MinTLSVersion,
		ValidationWebhook:        admissionHandler,
		MutationWebhook:          admissionHandler,
		MetricsListenAddress:     opts.MetricsListenAddress,
		MetricsCertificateSource: buildCertificateSource(log, opts.MetricsTLSConfig, restcfg),
		MetricsCipherSuites:      opts.MetricsTLSConfig.CipherSuites,
		MetricsMinTLSVersion:     opts.MetricsTLSConfig.MinTLSVersion,
	}
	for _, fn := range optionFunctions {
		fn(s)
	}
	return s, nil
}

func buildAdmissionChain(client kubernetes.Interface) (admission.PluginChain, error) {
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

	pluginChain := admission.PluginChain([]admission.Interface{
		cridentity.NewPlugin(),
		crapproval.NewPlugin(authorizer, client.Discovery()),
		resourcevalidation.NewPlugin(),
	})

	return pluginChain, nil
}

func buildCertificateSource(log logr.Logger, tlsConfig shared.TLSConfig, restCfg *rest.Config) tls.CertificateSource {
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
				LeafDuration:    tlsConfig.Dynamic.LeafDuration,
				RESTConfig:      restCfg,
			},
		}
	default:
		log.V(logf.WarnLevel).Info("serving insecurely as tls certificate data not provided")
	}
	return nil
}
