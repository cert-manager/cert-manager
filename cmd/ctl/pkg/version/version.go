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

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/versionchecker"
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
	*factory.Factory
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

func versionLong() string {
	return build.WithTemplate(`Print the cert-manager CLI version and the deployed cert-manager version.
The CLI version is embedded in the binary and directly displayed. Determining
the the deployed cert-manager version is done by querying the cert-manger
resources.  First, the tool looks at the labels of the cert-manager CRD
resources. Then, it searches for the labels of the resources related the the
cert-manager webhook linked in the CRDs.  It also tries to derive the version
from the docker image tag of that webhook service.  After gathering all this
version information, the tool checks if all versions are the same and returns
that version. If no version information is found or the found versions differ,
an error will be displayed.

The '--client' flag can be used to disable the logic that tries to determine the installed
cert-manager version.

Some example uses:
	$ {{.BuildName}} version
or
	$ {{.BuildName}} version --client
or
	$ {{.BuildName}} version --short
or
	$ {{.BuildName}} version -o yaml
`)
}

// NewCmdVersion returns a cobra command for fetching versions
func NewCmdVersion(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the cert-manager CLI version and the deployed cert-manager version",
		Long:  versionLong(),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate())
			cmdutil.CheckErr(o.Complete())
			cmdutil.CheckErr(o.Run(ctx))
		},
	}

	cmd.Flags().BoolVar(&o.ClientOnly, "client", o.ClientOnly, "If true, shows client version only (no server required).")
	cmd.Flags().BoolVar(&o.Short, "short", o.Short, "If true, print just the version number.")
	cmd.Flags().StringVarP(&o.Output, "output", "o", o.Output, "One of 'yaml' or 'json'.")

	o.Factory = factory.New(ctx, cmd)

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
func (o *Options) Complete() error {
	if o.ClientOnly {
		return nil
	}

	versionChecker, err := versionchecker.New(o.RESTConfig, scheme.Scheme)
	if err != nil {
		return err
	}
	o.VersionChecker = versionChecker
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
