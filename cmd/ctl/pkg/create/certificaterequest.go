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

package create

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	restclient "k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

var (
	long = templates.LongDesc(i18n.T(`
Create a cert-manager CertificateRequest resource for one-time Certificate issuing without auto renewal.`))

	example = templates.Examples(i18n.T(`
`))

	alias = []string{"cr"}
)

// Options is a struct to support renew command
type Options struct {
	CMClient   cmclient.Interface
	RESTConfig *restclient.Config

	// The Namespace that the CertificateRequest to be created resides in.
	// This flag registration is handled by cmdutil.Factory
	Namespace string
	// Path to the manifest for the Certificate resource (yaml file)
	FilePath string

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdRenew returns a cobra command for renewing Certificates
func NewCmdCreateCertficate(ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "certificaterequest",
		Aliases: alias,
		Short:   "Create a CertificateRequest resource",
		Long:    long,
		Example: example,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(factory))
			cmdutil.CheckErr(o.Run(args))
		},
	}

	cmd.Flags().StringVarP(&o.FilePath, "from-file", "f", o.FilePath, "Path to the manifest for the Certificate resource (yaml file) based on which the CertificateRequest is going to be created.")

	return cmd
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete(f cmdutil.Factory) error {
	var err error
	o.Namespace, _, err = f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	o.RESTConfig, err = f.ToRESTConfig()
	if err != nil {
		return err
	}

	o.CMClient, err = cmclient.NewForConfig(o.RESTConfig)
	if err != nil {
		return err
	}

	return nil
}

// Run executes renew command
func (o *Options) Run(args []string) error {
	return nil
}
