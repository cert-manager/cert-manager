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

package status

import (
	"fmt"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	restclient "k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	long = templates.LongDesc(i18n.T(`
Get details about the current status of a Certificate, including information on related resources like CertificateRequest or Order.`))

	example = templates.Examples(i18n.T(`
`))
)

// Options is a struct to support certificate status command
type Options struct {
	CMClient   cmclient.Interface
	RESTConfig *restclient.Config

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdCertStatus returns a cobra command for create CertificateRequest
func NewCmdCertStatus(ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Get details about the current status of a Certificate",
		Long:    long,
		Example: example,
		Run: func(cmd *cobra.Command, args []string) {
			o.Run(args)
		},
	}
	return cmd
}

func (o *Options) Run(args []string) {
	fmt.Fprintln(o.Out, "Status")
}
