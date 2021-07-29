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
	"k8s.io/kubectl/pkg/scheme"
	"sigs.k8s.io/yaml"

	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/versionchecker"
)

// Version is a struct for version information
type Version struct {
	ClientVersion *util.Version           `json:"clientVersion,omitempty"`
	ServerVersion *versionchecker.Version `json:"serverVersion,omitempty"`
}

// Options is a struct to support version command
type Options struct {
	// If true, don't try to retrieve the installed version
	ClientOnly bool

	// If true, only prints the version number.
	Short bool

	// Output is the target output format for the version string. This may be of
	// value "", "json" or "yaml".
	Output string

	VersionChecker versionchecker.Interface

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdVersion returns a cobra command for fetching versions
func NewCmdVersion(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the cert-manager kubectl plugin version and the deployed cert-manager version",
		Long:  "Print the cert-manager kubectl plugin version and the deployed cert-manager version",
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate())
			cmdutil.CheckErr(o.Complete(factory))
			cmdutil.CheckErr(o.Run(ctx))
		},
	}

	cmd.Flags().BoolVar(&o.ClientOnly, "client", o.ClientOnly, "If true, shows client version only (no server required).")
	cmd.Flags().BoolVar(&o.Short, "short", o.Short, "If true, print just the version number.")
	cmd.Flags().StringVarP(&o.Output, "output", "o", o.Output, "One of 'yaml' or 'json'.")
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

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete(factory cmdutil.Factory) error {
	if o.ClientOnly {
		return nil
	}

	restConfig, err := factory.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("Error: cannot create the REST config: %v", err)
	}

	o.VersionChecker, err = versionchecker.New(restConfig, scheme.Scheme)
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}
	return nil
}

// Run executes version command
func (o *Options) Run(ctx context.Context) error {
	var (
		serverVersion *versionchecker.Version
		serverErr     error
		versionInfo   Version
	)

	clientVersion := util.VersionInfo()
	versionInfo.ClientVersion = &clientVersion

	if !o.ClientOnly {
		serverVersion, serverErr = o.VersionChecker.Version(ctx)
		versionInfo.ServerVersion = serverVersion
	}

	switch o.Output {
	case "":
		if o.Short {
			fmt.Fprintf(o.Out, "Client Version: %s\n", clientVersion.GitVersion)
			if serverVersion != nil {
				fmt.Fprintf(o.Out, "Server Version: %s\n", serverVersion.Detected)
			}
		} else {
			fmt.Fprintf(o.Out, "Client Version: %s\n", fmt.Sprintf("%#v", clientVersion))
			if serverVersion != nil {
				fmt.Fprintf(o.Out, "Server Version: %s\n", fmt.Sprintf("%#v", serverVersion))
			}
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

	return serverErr
}
