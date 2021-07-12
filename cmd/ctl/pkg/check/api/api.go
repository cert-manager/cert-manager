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

package api

import (
	"context"
	"log"
	"time"

	"github.com/jetstack/cert-manager/pkg/util/cmapichecker"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	restclient "k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

// Options is a struct to support check api command
type Options struct {
	RESTConfig *restclient.Config

	// APIChecker is used to check that the cert-manager CRDs have been installed on the K8S
	// API server and that the cert-manager webhooks are all working
	APIChecker cmapichecker.Interface

	// If set to true, command will wait until creating resources against the api is possible
	Wait bool

	// Time before timeout when waiting
	Timeout time.Duration

	// Time between checks when waiting
	Interval time.Duration

	// Namespace that is used to dry-run create the certificate resource in
	Namespace string

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete(factory cmdutil.Factory) error {
	var err error

	o.Namespace, _, err = factory.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	o.RESTConfig, err = factory.ToRESTConfig()
	if err != nil {
		return err
	}

	o.APIChecker, err = cmapichecker.New(o.RESTConfig, o.Namespace)
	if err != nil {
		return err
	}

	return nil
}

// NewCmdCheckApi returns a cobra command for checking creating cert-manager resources against the K8S API server
func NewCmdCheckApi(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use: "api",
		Short: `
			This check attempts to perform a dry-run create of a cert-manager *v1alpha2*
			Certificate resource in order to verify that CRDs are installed and all the
			required webhooks are reachable by the K8S API server.
			We use v1alpha2 API to ensure that the API server has also connected to the
			cert-manager conversion webhook.
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(factory); err != nil {
				return err
			}
			return o.Run(ctx)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&o.Wait, "wait", true, "If set to true, command will wait until creating resources against the api is possible")
	cmd.Flags().DurationVar(&o.Timeout, "timeout", 30*time.Second, "Time before timeout when waiting, must include unit, e.g. 5s or 10m")
	cmd.Flags().DurationVar(&o.Interval, "interval", 5*time.Second, "Time between checks when waiting, must include unit, e.g. 5s or 10m")

	return cmd
}

// Run executes check api command
func (o *Options) Run(ctx context.Context) error {
	log.SetFlags(0) // Disable prefixing logs with timestamps.

	if !o.Wait {
		if err := o.APIChecker.Check(ctx); err != nil {
			return err
		}

		log.Print("The Kubernetes Api is ready to created cert-manager resources against")

		return nil
	}

	return wait.PollImmediate(o.Interval, o.Timeout, func() (done bool, err error) {
		if err := o.APIChecker.Check(ctx); err != nil {
			log.Printf("%v", err)
			return false, nil
		}

		log.Print("The Kubernetes Api is ready to created cert-manager resources against")

		return true, nil
	})
}
