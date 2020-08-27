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
	"fmt"
	"io"
	"net"

	"github.com/spf13/cobra"

	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	"github.com/jetstack/cert-manager/pkg/acme/webhook"
	whapi "github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apiserver"
)

const defaultEtcdPathPrefix = "/registry/acme.cert-manager.io"

type WebhookServerOptions struct {
	RecommendedOptions *genericoptions.RecommendedOptions

	SolverGroup string
	Solvers     []webhook.Solver

	StdOut io.Writer
	StdErr io.Writer
}

func NewWebhookServerOptions(out, errOut io.Writer, groupName string, solvers ...webhook.Solver) *WebhookServerOptions {
	o := &WebhookServerOptions{
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
	o.RecommendedOptions.AddFlags(flags)

	return cmd
}

func (o WebhookServerOptions) Validate(args []string) error {
	return nil
}

func (o *WebhookServerOptions) Complete() error {
	return nil
}

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

func (o WebhookServerOptions) RunWebhookServer(stopCh <-chan struct{}) error {
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
