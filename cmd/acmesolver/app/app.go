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
	"time"

	"github.com/spf13/cobra"

	"github.com/cert-manager/cert-manager/cmd/util"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/http/solver"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func NewACMESolverCommand(stopCh <-chan struct{}) *cobra.Command {
	s := new(solver.HTTP01Solver)

	cmd := &cobra.Command{
		Use:   "acmesolver",
		Short: "HTTP server used to solve ACME challenges.",
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCtx := util.ContextWithStopCh(context.Background(), stopCh)
			rootCtx = logf.NewContext(rootCtx, logf.Log, "acmesolver")
			log := logf.FromContext(rootCtx)

			completedCh := make(chan struct{})
			go func() {
				defer close(completedCh)
				<-stopCh
				// allow a timeout for graceful shutdown
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				if err := s.Shutdown(ctx); err != nil {
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

	return cmd
}
