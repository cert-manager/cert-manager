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

package version

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"sigs.k8s.io/yaml"

	"github.com/cert-manager/cert-manager/pkg/util"
)

// Options is a struct to support version command
type Options struct {
	// Output is the target output format for the version string. This may be of
	// value "", "json" or "yaml".
	Output string

	// If true, prints the version number.
	Short bool

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdVersion returns a cobra command for fetching versions
func NewCmdVersion(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the kubectl cert-manager version",
		Long:  "Print the kubectl cert-manager version",
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate())
			cmdutil.CheckErr(o.Run())
		},
	}

	cmd.Flags().StringVarP(&o.Output, "output", "o", "", "One of '', 'yaml' or 'json'.")
	cmd.Flags().BoolVar(&o.Short, "short", false, "If true, print just the version number.")

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate() error {
	switch o.Output {
	case "", "yaml", "json":
		return nil
	default:
		return errors.New(`--output must be '', 'yaml' or 'json'`)
	}
}

// Run executes version command
func (o *Options) Run() error {
	versionInfo := util.VersionInfo()

	switch o.Output {
	case "":
		if o.Short {
			fmt.Fprintf(o.Out, "%s\n", versionInfo.GitVersion)
		} else {
			fmt.Fprintf(o.Out, "%#v\n", versionInfo)
		}
	case "yaml":
		marshalled, err := yaml.Marshal(&versionInfo)
		if err != nil {
			return err
		}
		fmt.Fprint(o.Out, string(marshalled))
	case "json":
		marshalled, err := json.MarshalIndent(&versionInfo, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(o.Out, string(marshalled))
	default:
		// There is a bug in the program if we hit this case.
		// However, we follow a policy of never panicking.
		return fmt.Errorf("VersionOptions were not validated: --output=%q should have been rejected", o.Output)
	}

	return nil
}
