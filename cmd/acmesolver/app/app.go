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
	"time"

	"github.com/spf13/cobra"
	"k8s.io/component-base/logs"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/http/solver"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func NewACMESolverCommand(_ context.Context) *cobra.Command {
	s := new(solver.HTTP01Solver)
	logOptions := logs.NewOptions()

	cmd := &cobra.Command{
		Use:   "acmesolver",
		Short: "HTTP server used to solve ACME challenges.",

		SilenceErrors: true, // Errors are already logged when calling cmd.Execute()
		SilenceUsage:  true, // Don't print usage on every error

		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := logf.ValidateAndApply(logOptions); err != nil {
				return fmt.Errorf("error validating options: %s", err)
			}

			return nil
		},
		// nolint:contextcheck // False positive
		RunE: func(cmd *cobra.Command, args []string) error {
			runCtx := cmd.Context()
			log := logf.FromContext(runCtx)

			completedCh := make(chan struct{})
			go func() {
				defer close(completedCh)
				<-runCtx.Done()

				// allow a timeout for graceful shutdown
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				// nolint: contextcheck
				if err := s.Shutdown(shutdownCtx); err != nil {
					log.Error(err, "error shutting down acmesolver server")
				}
			}()

			if err := s.Listen(log); err != nil {
				return err
			}

			<-completedCh

			return nil
		},
	}

	cmd.Flags().IntVar(&s.ListenPort, "listen-port", 8089, "the port number to listen on for connections")
	cmd.Flags().StringVar(&s.Domain, "domain", "", "the domain name to verify")
	cmd.Flags().StringVar(&s.Token, "token", "", "the challenge token to verify against")
	cmd.Flags().StringVar(&s.Key, "key", "", "the challenge key to respond with")

	// TODO(@inteon): use flags to configure the log configuration (https://github.com/cert-manager/cert-manager/issues/6021)

	return cmd
}
