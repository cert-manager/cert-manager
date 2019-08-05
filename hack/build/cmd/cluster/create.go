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

package cluster

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Masterminds/semver"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	"github.com/jetstack/cert-manager/hack/build/cmd/options"
	"github.com/jetstack/cert-manager/hack/build/internal/bazel"
	"github.com/jetstack/cert-manager/hack/build/internal/cluster"
	logf "github.com/jetstack/cert-manager/hack/build/internal/log"
)

func RegisterCreateCmd(rootOpts *options.Root, clusterOpts *options.Cluster, rootCmd *cobra.Command) {
	log := logf.Log.WithName("create")
	ctx := context.Background()

	opts := &options.ClusterCreate{}
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create clusters used for development and testing",
		Run: func(cmd *cobra.Command, args []string) {
			stdout := os.Stdout
			if !rootOpts.Debug {
				stdout = nil
			}

			ver := semver.MustParse(opts.KubeVersion)

			configPath, err := kindConfigForVersion(ver, rootOpts.RepoRoot)
			if err != nil {
				log.Error(err, "fail to determine kind config path")
				os.Exit(1)
			}

			imageName, err := kindImageForVersion(ctx, stdout, log.V(4), rootOpts.RepoRoot, ver)
			if err != nil {
				log.Error(err, "error fetching kind image for kube-version", "kube_version", opts.KubeVersion)
				os.Exit(1)
			}

			cl := &cluster.Cluster{
				KindClusterName: clusterOpts.Name,
				KindConfigPath:  configPath,
				KindImage:       imageName,
				Log:             log.V(4),
				Stdout:          stdout,
			}

			log.Info("creating kind cluster...")
			if err := cl.Create(); err != nil {
				log.Error(err, "error creating cluster")
				os.Exit(1)
			}
		},
	}
	opts.AddFlags(createCmd.Flags())

	rootCmd.AddCommand(createCmd)
}

func kindImageForVersion(ctx context.Context, stdout io.Writer, log logr.InfoLogger, rootDir string, v *semver.Version) (string, error) {
	strippedPath := fmt.Sprintf("hack/bin:kind-%d.%d", v.Major(), v.Minor())
	imageTarget := "//" + strippedPath
	imageName := "bazel/" + strippedPath
	img := &bazel.ContainerImage{
		Target:       imageTarget,
		WorkspaceDir: rootDir,
		Stdout:       stdout,
		Log:          log,
	}
	if err := img.Export(ctx); err != nil {
		return "", err
	}
	// this is inferred by the image target name
	return imageName, nil
}

func kindConfigForVersion(v *semver.Version, repoRoot string) (string, error) {
	if v.Major() != 1 {
		return "", fmt.Errorf("unsupported version %q", v.String())
	}
	configVers := ""
	switch v.Minor() {
	case 11:
		configVers = "v1alpha2"
	case 12:
		configVers = "v1alpha3"
	case 13, 14:
		configVers = "v1beta1"
	default:
		if v.Minor() <= 14 {
			return "", fmt.Errorf("unsupported version %q", v.String())
		}
		// default to v1beta2
		configVers = "v1beta2"
	}

	return filepath.Join(repoRoot, "test", "fixtures", "kind", "config-"+configVers+".yaml"), nil
}
