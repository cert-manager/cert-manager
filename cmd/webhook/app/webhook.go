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
	"fmt"
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	cliflag "k8s.io/component-base/cli/flag"

	cmdutil "github.com/jetstack/cert-manager/cmd/util"
	"github.com/jetstack/cert-manager/cmd/webhook/app/options"
	"github.com/jetstack/cert-manager/internal/apis/config"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/webhook"
	"github.com/jetstack/cert-manager/pkg/webhook/authority"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers"
	"github.com/jetstack/cert-manager/pkg/webhook/server"
	"github.com/jetstack/cert-manager/pkg/webhook/server/tls"
)

var validationHook handlers.ValidatingAdmissionHook = handlers.NewRegistryBackedValidator(logf.Log, webhook.Scheme, webhook.ValidationRegistry)
var mutationHook handlers.MutatingAdmissionHook = handlers.NewRegistryBackedMutator(logf.Log, webhook.Scheme, webhook.MutationRegistry)
var conversionHook handlers.ConversionHook = handlers.NewSchemeBackedConverter(logf.Log, webhook.Scheme)

func NewServerWithOptions(log logr.Logger, _ options.WebhookFlags, opts config.WebhookConfiguration) (*server.Server, error) {
	restcfg, err := clientcmd.BuildConfigFromFlags(opts.APIServerHost, opts.KubeConfig)
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
	case opts.TLSConfig.FilesystemConfigProvided():
		log.V(logf.InfoLevel).Info("using TLS certificate from local filesystem", "private_key_path", opts.TLSConfig.Filesystem.KeyFile, "certificate", opts.TLSConfig.Filesystem.CertFile)
		source = &tls.FileCertificateSource{
			CertPath: opts.TLSConfig.Filesystem.CertFile,
			KeyPath:  opts.TLSConfig.Filesystem.KeyFile,
			Log:      log,
		}
	case opts.TLSConfig.DynamicConfigProvided():
		restcfg, err := clientcmd.BuildConfigFromFlags("", opts.KubeConfig)
		if err != nil {
			return nil, err
		}

		log.V(logf.InfoLevel).Info("using dynamic certificate generating using CA stored in Secret resource", "secret_namespace", opts.TLSConfig.Dynamic.SecretNamespace, "secret_name", opts.TLSConfig.Dynamic.SecretName)
		source = &tls.DynamicSource{
			DNSNames: opts.TLSConfig.Dynamic.DNSNames,
			Authority: &authority.DynamicAuthority{
				SecretNamespace: opts.TLSConfig.Dynamic.SecretNamespace,
				SecretName:      opts.TLSConfig.Dynamic.SecretName,
				RESTConfig:      restcfg,
				Log:             log,
			},
			Log: log,
		}
	default:
		log.V(logf.WarnLevel).Info("serving insecurely as tls certificate data not provided")
	}

	return &server.Server{
		ListenAddr:        fmt.Sprintf(":%d", *opts.SecurePort),
		HealthzAddr:       fmt.Sprintf(":%d", *opts.HealthzPort),
		EnablePprof:       opts.EnablePprof,
		PprofAddr:         opts.PprofAddress,
		CertificateSource: source,
		CipherSuites:      opts.TLSConfig.CipherSuites,
		MinTLSVersion:     opts.TLSConfig.MinTLSVersion,
		ValidationWebhook: validationHook,
		MutationWebhook:   mutationHook,
		ConversionWebhook: conversionHook,
		Log:               log,
	}, nil
}

const componentWebhook = "webhook"

func NewServerCommand(stopCh <-chan struct{}) *cobra.Command {
	ctx := cmdutil.ContextWithStopCh(context.Background(), stopCh)
	ctx = logf.NewContext(ctx, nil, "webhook")
	log := logf.FromContext(ctx)

	cleanFlagSet := pflag.NewFlagSet(componentWebhook, pflag.ContinueOnError)
	// Replaces all instances of `_` in flag names with `-`
	cleanFlagSet.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	webhookFlags := options.NewWebhookFlags()
	webhookConfig, err := options.NewWebhookConfiguration()
	if err != nil {
		log.Error(err, "Failed to create new webhook configuration")
		os.Exit(1)
	}

	cmd := &cobra.Command{
		Use:   componentWebhook,
		Short: fmt.Sprintf("Webhook component providing API validation, mutation and conversion functionality for cert-manager (%s) (%s)", util.AppVersion, util.AppGitCommit),
		// The webhook has special flag parsing requirements to handle precedence of providing
		// configuration via versioned configuration files and flag values.
		// Setting DisableFlagParsing=true prevents Cobra from interfering with flag parsing
		// at all, and instead we handle it all in the RunE below.
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			// initial flag parse, since we disable cobra's flag parsing
			if err := cleanFlagSet.Parse(args); err != nil {
				log.Error(err, "Failed to parse kubelet flag")
				cmd.Usage()
				os.Exit(1)
			}

			// check if there are non-flag arguments in the command line
			cmds := cleanFlagSet.Args()
			if len(cmds) > 0 {
				log.Error(nil, "Unknown command", "command", cmds[0])
				cmd.Usage()
				os.Exit(1)
			}

			// short-circuit on help
			help, err := cleanFlagSet.GetBool("help")
			if err != nil {
				log.Info(`"help" flag is non-bool, programmer error, please correct`)
				os.Exit(1)
			}
			if help {
				cmd.Help()
				return
			}

			srv, err := NewServerWithOptions(log, *webhookFlags, *webhookConfig)
			if err != nil {
				log.Error(err, "Failed initialising server")
				os.Exit(1)
			}

			if err := srv.Run(stopCh); err != nil {
				log.Error(err, "Failed running server")
				os.Exit(1)
			}
		},
	}

	webhookFlags.AddFlags(cleanFlagSet)
	options.AddConfigFlags(cleanFlagSet, webhookConfig)

	cleanFlagSet.BoolP("help", "h", false, fmt.Sprintf("help for %s", cmd.Name()))

	// ugly, but necessary, because Cobra's default UsageFunc and HelpFunc pollute the flagset with global flags
	const usageFmt = "Usage:\n  %s\n\nFlags:\n%s"
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine(), cleanFlagSet.FlagUsagesWrapped(2))
		return nil
	})
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine(), cleanFlagSet.FlagUsagesWrapped(2))
	})

	return cmd
}
