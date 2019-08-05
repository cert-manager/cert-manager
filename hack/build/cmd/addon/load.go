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

package addon

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	"github.com/jetstack/cert-manager/hack/build/cmd/options"
	"github.com/jetstack/cert-manager/hack/build/internal/bazel"
	"github.com/jetstack/cert-manager/hack/build/internal/cluster"
	logf "github.com/jetstack/cert-manager/hack/build/internal/log"
)

func RegisterLoadCmd(rootOpts *options.Root, addonOpts *options.Addon, rootCmd *cobra.Command) {
	log := logf.Log.WithName("load")

	opts := &options.AddonLoad{}
	cmd := &cobra.Command{
		Use:   "load",
		Short: "Load addon images into the kind testing cluster",
		Run: func(cmd *cobra.Command, args []string) {
			cl := &cluster.Cluster{
				KindClusterName: opts.KindClusterName,
				Log:             log.V(4),
			}
			if rootOpts.Debug {
				cl.Stdout = os.Stdout
			}
			var wg sync.WaitGroup
			for _, component := range addonOpts.Components {
				wg.Add(1)
				nameCh := make(chan string)
				go func(component string) {
					defer close(nameCh)
					log := log.WithValues("component", component)

					log.Info("building docker image")
					ctx := context.Background()
					imageName, err := buildAndExport(ctx, log, rootOpts.RepoRoot, rootOpts.Debug, component)
					if err != nil {
						log.Error(err, "error building image")
						os.Exit(1)
					}
					nameCh <- imageName
					log.Info("built and exported docker image")
				}(component)
				go func() {
					defer wg.Done()
					imageName := <-nameCh

					if err := cl.Load(imageName); err != nil {
						log.Error(err, "failed to load docker image into kind container")
						os.Exit(1)
					}

					log.Info("loaded docker image", "image_name", imageName)
				}()
			}
			wg.Wait()
			log.Info("loaded all images")
		},
	}
	opts.AddFlags(cmd.Flags())

	rootCmd.AddCommand(cmd)
}

func buildAndExport(ctx context.Context, log logr.Logger, repoRoot string, debug bool, component string) (string, error) {
	repo, tag := imageRefForAddon(component)
	imageName := repo + ":" + tag

	log.Info("using root", "root", repoRoot)
	ci := &bazel.ContainerImage{
		Target:       "//test/e2e/addon/" + component + ":image",
		WorkspaceDir: repoRoot,
		Log:          log.V(4),
	}
	if debug {
		ci.Stdout = os.Stdout
	}

	if err := ci.Export(ctx, imageName); err != nil {
		return "", fmt.Errorf("failed to export image")
	}

	return imageName, nil
}

func imageRefForAddon(s string) (repo, tag string) {
	return "bazel/test/e2e/addon/" + s, "v0.0.0-bazel"
}
