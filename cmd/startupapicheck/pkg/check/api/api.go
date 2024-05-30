/*
Copyright 2023 The cert-manager Authors.

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
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/wait"

	cmcmdutil "github.com/cert-manager/cert-manager/internal/cmd/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/cmapichecker"
	"github.com/cert-manager/cert-manager/startupapicheck-binary/pkg/factory"
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

	*factory.Factory
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete() error {
	var err error

	o.APIChecker, err = cmapichecker.New(
		o.RESTConfig,
		o.Namespace,
	)
	if err != nil {
		return err
	}

	return nil
}

// NewCmdCheckApi returns a cobra command for checking creating cert-manager resources against the K8S API server
func NewCmdCheckApi(setupCtx context.Context) *cobra.Command {
	o := &Options{}

	cmd := &cobra.Command{
		Use:   "api",
		Short: "Check if the cert-manager API is ready",
		Long: `
This check attempts to perform a dry-run create of a cert-manager *v1*
Certificate resource in order to verify that CRDs are installed and all the
required webhooks are reachable by the K8S API server.`,

		PreRunE: func(cmd *cobra.Command, args []string) error {
			return o.Complete()
		},
		// nolint:contextcheck // False positive
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Run(cmd.Context(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().DurationVar(&o.Wait, "wait", 0, "Wait until the cert-manager API is ready (default 0s = poll once)")
	cmd.Flags().DurationVar(&o.Interval, "interval", 5*time.Second, "Time between checks when waiting, must include unit, e.g. 1m or 10m")

	o.Factory = factory.New(cmd)

	return cmd
}

// Run executes check api command
func (o *Options) Run(ctx context.Context, out io.Writer) error {
	log := logf.FromContext(ctx, "checkAPI")

	start := time.Now()
	var lastError error
	pollErr := wait.PollUntilContextCancel(ctx, o.Interval, true, func(ctx context.Context) (bool, error) {
		if err := o.APIChecker.Check(ctx); err != nil {
			simpleError := cmapichecker.TranslateToSimpleError(err)
			if simpleError != nil {
				log.V(2).Info("Not ready", "err", simpleError, "underlyingError", err)
				lastError = simpleError
			} else {
				log.V(2).Info("Not ready", "err", err)
				lastError = err
			}

			if time.Since(start) > o.Wait {
				return false, context.DeadlineExceeded
			}
			return false, nil
		}

		return true, nil
	})

	if pollErr != nil {
		if errors.Is(pollErr, context.DeadlineExceeded) && o.Wait > 0 {
			log.V(2).Info("Timed out", "after", o.Wait, "err", pollErr)
			cmcmdutil.SetExitCode(pollErr)
		} else {
			cmcmdutil.SetExitCode(lastError)
		}

		return lastError
	}

	fmt.Fprintln(out, "The cert-manager API is ready")

	return nil
}
