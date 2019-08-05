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

package certmanager

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/jetstack/cert-manager/hack/build/cmd/options"
	logf "github.com/jetstack/cert-manager/hack/build/internal/log"
)

func RegisterBuildCmd(rootOpts *options.Root, cmOpts *options.CertManager, rootCmd *cobra.Command) {
	log := logf.Log.WithName("build")

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build cert-manager images and export them to the local docker daemon",
		Run: func(cmd *cobra.Command, args []string) {
			for _, component := range cmOpts.Components {
				log := log.WithValues("component", component)

				log.Info("building docker image")
				ctx := context.Background()
				imageName, err := buildAndExport(ctx, log, rootOpts.RepoRoot, rootOpts.Debug, cmOpts.DockerRepo, component, cmOpts.AppVersion)
				if err != nil {
					log.Error(err, "error building image")
					os.Exit(1)
				}
				log.Info("built and exported docker image", "image_name", imageName)
			}
			log.Info("built all images")
		},
	}

	rootCmd.AddCommand(cmd)
}
