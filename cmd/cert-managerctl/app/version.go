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

package app

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jetstack/cert-manager/pkg/util"
)

var versionCmd = &cobra.Command{
	Args:  cobra.NoArgs,
	Use:   "version",
	Short: "prints the cert-managerctl CLI version",
	Long:  "prints the cert-managerctl CLI version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf(fmt.Sprintf("version=%s git-commit=%s\nNote, this CLI tool is currently marked as experimental.\n", util.AppVersion, util.AppGitCommit))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
