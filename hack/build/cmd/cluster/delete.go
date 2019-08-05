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
	"os"

	"github.com/spf13/cobra"

	"github.com/jetstack/cert-manager/hack/build/cmd/options"
	"github.com/jetstack/cert-manager/hack/build/internal/cluster"
	logf "github.com/jetstack/cert-manager/hack/build/internal/log"
)

func RegisterDeleteCmd(rootOpts *options.Root, clusterOpts *options.Cluster, rootCmd *cobra.Command) {
	log := logf.Log.WithName("create")

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete clusters used for development and testing",
		Run: func(cmd *cobra.Command, args []string) {
			cl := cluster.Cluster{
				KindClusterName: clusterOpts.Name,
				Log:             log.V(4),
			}
			if rootOpts.Debug {
				cl.Stdout = os.Stdout
			}

			log.Info("deleting kind cluster...")
			if err := cl.Delete(); err != nil {
				log.Error(err, "error deleting cluster")
				os.Exit(1)
			}
		},
	}

	rootCmd.AddCommand(cmd)
}
