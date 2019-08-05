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

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jetstack/cert-manager/hack/build/cmd/options"
	"github.com/jetstack/cert-manager/hack/release/pkg/log"
)

func Execute() {
	rootCmd := RegisterRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func RegisterRootCmd() *cobra.Command {
	opts := &options.Root{}
	rootCmd := &cobra.Command{
		Use:   "build",
		Short: "A tool for interacting with the cert-manager build system",
	}
	opts.AddFlags(rootCmd.PersistentFlags())
	log.InitLogs(rootCmd.PersistentFlags())

	RegisterClusterCmd(opts, rootCmd)
	RegisterCertManagerCmd(opts, rootCmd)
	RegisterAddonCmd(opts, rootCmd)

	return rootCmd
}
