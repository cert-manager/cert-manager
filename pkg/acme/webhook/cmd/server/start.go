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
	"fmt"
	"net"

	"github.com/spf13/cobra"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/component-base/logs"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apiserver"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type WebhookServerOptions struct {
	Logging *logs.Options

	RecommendedOptions *genericoptions.RecommendedOptions

	SolverGroup string
	Solvers     []webhook.Solver
}

func NewWebhookServerOptions(groupName string, solvers ...webhook.Solver) *WebhookServerOptions {
	o := &WebhookServerOptions{
		Logging: logs.NewOptions(),

		RecommendedOptions: genericoptions.NewRecommendedOptions(
			"<UNUSED>",
			apiserver.Codecs.LegacyCodec(whapi.SchemeGroupVersion),
		),

		SolverGroup: groupName,
		Solvers:     solvers,
	}
	o.RecommendedOptions.Etcd = nil
	o.RecommendedOptions.Admission = nil
	o.RecommendedOptions.Features.EnablePriorityAndFairness = false

	return o
}

func NewCommandStartWebhookServer(_ context.Context, groupName string, solvers ...webhook.Solver) *cobra.Command {
	o := NewWebhookServerOptions(groupName, solvers...)

	cmd := &cobra.Command{
		Short: "Launch an ACME solver API server",
		Long:  "Launch an ACME solver API server",
		// nolint:contextcheck // False positive
		RunE: func(c *cobra.Command, args []string) error {
			runCtx := c.Context()

			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			if err := o.RunWebhookServer(runCtx); err != nil {
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
func (o WebhookServerOptions) RunWebhookServer(ctx context.Context) error {
	config, err := o.Config()
	if err != nil {
		return err
	}

	server, err := config.Complete().New()
	if err != nil {
		return err
	}
	return server.GenericAPIServer.PrepareRun().RunWithContext(ctx)
}
