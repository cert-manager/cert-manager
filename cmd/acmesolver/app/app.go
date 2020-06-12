/*
Copyright 2020 The Jetstack cert-manager contributors.

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

	"github.com/jetstack/cert-manager/pkg/issuer/acme/http/solver"
	"github.com/spf13/cobra"
)

func NewACMESolverCommand(ctx context.Context) *cobra.Command {
	var (
		listenPort int
		domain     string
		token      string
		key        string
	)

	cmd := &cobra.Command{
		Use:   "acmesolver",
		Short: "HTTP server used to solver ACME challenges.",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &solver.HTTP01Solver{
				ListenPort: listenPort,
				Domain:     domain,
				Token:      token,
				Key:        key,
			}

			if err := s.Listen(ctx); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&listenPort, "listen-port", 8089, "the port number to listen on for connections")
	cmd.Flags().StringVar(&domain, "domain", "", "the domain name to verify")
	cmd.Flags().StringVar(&token, "token", "", "the challenge token to verify against")
	cmd.Flags().StringVar(&key, "key", "", "the challenge key to respond with")

	return cmd
}
