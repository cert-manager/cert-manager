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

package app

import (
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/jetstack/cert-manager/cmd/webhook/app/options"
	"github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/webhook"
	"github.com/jetstack/cert-manager/pkg/webhook/authority"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers"
	"github.com/jetstack/cert-manager/pkg/webhook/server"
	"github.com/jetstack/cert-manager/pkg/webhook/server/tls"
)

var validationHook handlers.ValidatingAdmissionHook = handlers.NewRegistryBackedValidator(logs.Log, webhook.Scheme, webhook.ValidationRegistry)
var mutationHook handlers.MutatingAdmissionHook = handlers.NewSchemeBackedDefaulter(logs.Log, webhook.Scheme)
var conversionHook handlers.ConversionHook = handlers.NewSchemeBackedConverter(logs.Log, webhook.Scheme)

func RunServer(log logr.Logger, opts options.WebhookOptions, stopCh <-chan struct{}) error {
	srv, err := NewServerWithOptions(log, opts)
	if err != nil {
		return err
	}

	return srv.Run(stopCh)
}

func NewServerWithOptions(log logr.Logger, opts options.WebhookOptions) (*server.Server, error) {
	var source tls.CertificateSource
	switch {
	case options.FileTLSSourceEnabled(opts):
		log.Info("using TLS certificate from local filesystem", "private_key_path", opts.TLSKeyFile, "certificate", opts.TLSCertFile)
		source = &tls.FileCertificateSource{
			CertPath: opts.TLSCertFile,
			KeyPath:  opts.TLSKeyFile,
			Log:      log,
		}
	case options.DynamicTLSSourceEnabled(opts):
		restcfg, err := clientcmd.BuildConfigFromFlags("", opts.Kubeconfig)
		if err != nil {
			return nil, err
		}

		log.Info("using dynamic certificate generating using CA stored in Secret resource", "secret_namespace", opts.DynamicServingCASecretNamespace, "secret_name", opts.DynamicServingCASecretName)
		source = &tls.DynamicSource{
			DNSNames: opts.DynamicServingDNSNames,
			Authority: &authority.DynamicAuthority{
				SecretNamespace: opts.DynamicServingCASecretNamespace,
				SecretName:      opts.DynamicServingCASecretName,
				RESTConfig:      restcfg,
				Log:             log,
			},
			Log: log,
		}
	default:
		log.Info("warning: serving insecurely as tls certificate data not provided")
	}

	return &server.Server{
		ListenAddr:        fmt.Sprintf(":%d", opts.ListenPort),
		HealthzAddr:       fmt.Sprintf(":%d", opts.HealthzPort),
		EnablePprof:       true,
		CertificateSource: source,
		CipherSuites:      opts.TLSCipherSuites,
		MinTLSVersion:     opts.MinTLSVersion,
		ValidationWebhook: validationHook,
		MutationWebhook:   mutationHook,
		ConversionWebhook: conversionHook,
		Log:               log,
	}, nil
}
