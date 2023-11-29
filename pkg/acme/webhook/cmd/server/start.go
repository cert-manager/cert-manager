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
	"fmt"
	"io"
	"net"

	"github.com/spf13/cobra"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/features"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/logs"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apiserver"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const defaultEtcdPathPrefix = "/registry/acme.cert-manager.io"

type WebhookServerOptions struct {
	Logging *logs.Options

	RecommendedOptions *genericoptions.RecommendedOptions

	SolverGroup string
	Solvers     []webhook.Solver

	StdOut io.Writer
	StdErr io.Writer
}

func NewWebhookServerOptions(out, errOut io.Writer, groupName string, solvers ...webhook.Solver) *WebhookServerOptions {
	o := &WebhookServerOptions{
		Logging: logs.NewOptions(),

		// TODO we will nil out the etcd storage options.  This requires a later level of k8s.io/apiserver
		RecommendedOptions: genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			apiserver.Codecs.LegacyCodec(whapi.SchemeGroupVersion),
		),

		SolverGroup: groupName,
		Solvers:     solvers,

		StdOut: out,
		StdErr: errOut,
	}
	o.RecommendedOptions.Etcd = nil
	o.RecommendedOptions.Admission = nil

	return o
}

func NewCommandStartWebhookServer(out, errOut io.Writer, stopCh <-chan struct{}, groupName string, solvers ...webhook.Solver) *cobra.Command {
	o := NewWebhookServerOptions(out, errOut, groupName, solvers...)

	cmd := &cobra.Command{
		Short: "Launch an ACME solver API server",
		Long:  "Launch an ACME solver API server",
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			if err := o.RunWebhookServer(stopCh); err != nil {
				return err
			}
			return nil
		},
	}

	flags := cmd.Flags()
	logf.AddFlags(o.Logging, flags)
	o.RecommendedOptions.AddFlags(flags)

	return cmd
}

func (o WebhookServerOptions) Validate(args []string) error {
	if err := logf.ValidateAndApply(o.Logging); err != nil {
		return err
	}

	if errs := o.RecommendedOptions.Validate(); len(errs) > 0 {
		return fmt.Errorf("error validating recommended options: %v", errs)
	}

	return nil
}

func (o *WebhookServerOptions) Complete() error {
	return nil
}

// Config creates a new webhook server config that includes generic upstream
// apiserver options, rest client config and the Solvers configured for this
// webhook server
func (o WebhookServerOptions) Config() (*apiserver.Config, error) {
	// TODO have a "real" external address
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	if err := o.RecommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	config := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			SolverGroup: o.SolverGroup,
			Solvers:     o.Solvers,
		},
	}
	return config, nil
}

// RunWebhookServer creates a new apiserver, registers an API Group for each of
// the configured solvers and runs the new apiserver.
func (o WebhookServerOptions) RunWebhookServer(stopCh <-chan struct{}) error {
	// extension apiserver does not need priority and fairness.
	// TODO: this is a short term fix; when APF graduates we will need to
	// find another way. Alternatives are either to find a way how to
	// disable APF controller (without the feature gate), run the controller
	// (create RBAC and ensure required resources are installed) or do some
	// bigger refactor of this project that could solve the problem
	utilruntime.Must(utilfeature.DefaultMutableFeatureGate.Set(fmt.Sprintf("%s=false", features.APIPriorityAndFairness)))
	config, err := o.Config()
	if err != nil {
		return err
	}

	server, err := config.Complete().New()
	if err != nil {
		return err
	}
	return server.GenericAPIServer.PrepareRun().Run(stopCh)
}
