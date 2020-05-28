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
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	long = templates.LongDesc(i18n.T(`
Create a cert-manager CertificateRequest resource for one-time Certificate issuing without auto renewal.`))

	example = templates.Examples(i18n.T(`
`))

	alias = []string{"cr"}
)

// NewCmdRenew returns a cobra command for renewing Certificates
func NewCmdCreateCertficate(ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	//o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "certificaterequest",
		Aliases: alias,
		Short:   "Create a CertificateRequest resource",
		Long:    long,
		Example: example,
		//Run: func(cmd *cobra.Command, args []string) {
		//	cmdutil.CheckErr(o.Complete(factory))
		//	cmdutil.CheckErr(o.Validate(cmd, args))
		//	cmdutil.CheckErr(o.Run(args))
		//},
	}

	// TODO: add flags
	//cmd.Flags().StringVarP(&o.LabelSelector, "selector", "l", o.LabelSelector, "Selector (label query) to filter on, supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)")
	//cmd.Flags().BoolVarP(&o.AllNamespaces, "all-namespaces", "A", o.AllNamespaces, "If present, mark Certificates across namespaces for manual renewal. Namespace in current context is ignored even if specified with --namespace.")
	//cmd.Flags().BoolVar(&o.All, "all", o.All, "Renew all Certificates in the given Namespace, or all namespaces with --all-namespaces enabled.")

	return cmd
}
