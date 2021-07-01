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

package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/jetstack/cert-manager/cmd/webhook/app/options"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/cmapichecker"
	"github.com/jetstack/cert-manager/pkg/webhook"
	"github.com/jetstack/cert-manager/pkg/webhook/authority"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers"
	"github.com/jetstack/cert-manager/pkg/webhook/server"
	"github.com/jetstack/cert-manager/pkg/webhook/server/tls"
)

const defaultAPICheckerNamespace = "default"

var validationHook handlers.ValidatingAdmissionHook = handlers.NewRegistryBackedValidator(logf.Log, webhook.Scheme, webhook.ValidationRegistry)
var mutationHook handlers.MutatingAdmissionHook = handlers.NewRegistryBackedMutator(logf.Log, webhook.Scheme, webhook.MutationRegistry)
var conversionHook handlers.ConversionHook = handlers.NewSchemeBackedConverter(logf.Log, webhook.Scheme)

func NewServerWithOptions(log logr.Logger, opts options.WebhookOptions) (*server.Server, error) {
	restcfg, err := clientcmd.BuildConfigFromFlags(opts.APIServerHost, opts.Kubeconfig)
	if err != nil {
		return nil, err
	}

	cl, err := kubernetes.NewForConfig(restcfg)
	if err != nil {
		return nil, fmt.Errorf("error creating kubernetes client: %s", err)
	}
	validationHook.InitPlugins(cl)

	var source tls.CertificateSource
	switch {
	case options.FileTLSSourceEnabled(opts):
		log.V(logf.InfoLevel).Info("using TLS certificate from local filesystem", "private_key_path", opts.TLSKeyFile, "certificate", opts.TLSCertFile)
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

		log.V(logf.InfoLevel).Info("using dynamic certificate generating using CA stored in Secret resource", "secret_namespace", opts.DynamicServingCASecretNamespace, "secret_name", opts.DynamicServingCASecretName)
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
		log.V(logf.WarnLevel).Info("serving insecurely as tls certificate data not provided")
	}
	apiCheckerNamespace, err := util.GetInClusterNamespace()
	if err != nil {
		if !errors.Is(err, util.ErrNotInCluster) {
			return nil, err
		}
		log.V(logf.WarnLevel).Info(
			"Overriding namespace for API health checks",
			"namespace", defaultAPICheckerNamespace,
			"reason", err)
		apiCheckerNamespace = defaultAPICheckerNamespace
	}

	apiChecker, err := cmapichecker.New(restcfg, apiCheckerNamespace)
	if err != nil {
		return nil, err
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
		APIChecker:        apiChecker,
	}, nil
}

func NewServerCommand(stopCh <-chan struct{}) *cobra.Command {
	var opts options.WebhookOptions

	cmd := &cobra.Command{
		Use:   "webhook",
		Short: fmt.Sprintf("Webhook component providing API validation, mutation and conversion functionality for cert-manager (%s) (%s)", util.AppVersion, util.AppGitCommit),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := util.ContextWithStopCh(context.Background(), stopCh)
			ctx = logf.NewContext(ctx, nil, "webhook")
			log := logf.FromContext(ctx)

			srv, err := NewServerWithOptions(log, opts)
			if err != nil {
				return err
			}

			return srv.Run(stopCh)
		},
	}

	opts.AddFlags(cmd.Flags())

	return cmd
}
