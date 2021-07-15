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
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/jetstack/cert-manager/pkg/util/cmapichecker"
)

// Options is a struct to support check api command
type Options struct {
	// APIChecker is used to check that the cert-manager CRDs have been installed on the K8S
	// API server and that the cert-manager webhooks are all working
	APIChecker cmapichecker.Interface

	// Time before timeout when waiting
	Wait time.Duration

	// Time between checks when waiting
	Interval time.Duration

	// Namespace that is used to dry-run create the certificate resource in
	Namespace string

	// Print details regarding encountered errors
	Verbose bool

	genericclioptions.IOStreams
}

var checkApiDesc = templates.LongDesc(i18n.T(`
This check attempts to perform a dry-run create of a cert-manager *v1alpha2*
Certificate resource in order to verify that CRDs are installed and all the
required webhooks are reachable by the K8S API server.
We use v1alpha2 API to ensure that the API server has also connected to the
cert-manager conversion webhook.`))

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
		return fmt.Errorf("Error: cannot get the namespace: %v", err)
	}

	restConfig, err := factory.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("Error: cannot create the REST config: %v", err)
	}

	// We pass the scheme that is used in the RESTConfig's NegotiatedSerializer,
	// this makes sure that the cmapi is also added to NegotiatedSerializer's scheme
	// see: https://github.com/jetstack/cert-manager/pull/4205#discussion_r668660271
	o.APIChecker, err = cmapichecker.New(restConfig, scheme.Scheme, o.Namespace)
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	return nil
}

// NewCmdCheckApi returns a cobra command for checking creating cert-manager resources against the K8S API server
func NewCmdCheckApi(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:   "api",
		Short: "This check attempts to perform a dry-run create of a cert-manager Certificate",
		Long:  checkApiDesc,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(factory); err != nil {
				return err
			}
			return o.Run(ctx)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().DurationVar(&o.Wait, "wait", 1*time.Minute, "Time before timeout when waiting, must include unit, e.g. 0s or 20s")
	cmd.Flags().DurationVar(&o.Interval, "interval", 5*time.Second, "Time between checks when waiting, must include unit, e.g. 1m or 10m")
	cmd.Flags().BoolVarP(&o.Verbose, "verbose", "v", false, "Print details regarding encountered errors")

	return cmd
}

// Run executes check api command
func (o *Options) Run(ctx context.Context) error {
	pollContext, cancel := context.WithTimeout(ctx, o.Wait)
	defer cancel()

	pollErr := wait.PollImmediateUntil(o.Interval, func() (done bool, err error) {
		if err := o.APIChecker.Check(ctx); err != nil {
			if o.Verbose {
				fmt.Fprintf(o.ErrOut, "Not ready: %v (%v)\n", err, err.Cause())
			} else {
				fmt.Fprintf(o.ErrOut, "Not ready: %v\n", err)
			}
			return false, nil
		}

		fmt.Fprintln(o.Out, "The cert-manager API is ready")

		return true, nil
	}, pollContext.Done())

	if pollErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return pollErr
	}

	return nil
}
