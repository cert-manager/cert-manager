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

package certificate

import (
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/certificate/status"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

func NewCmdCertificate(ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	cmds := &cobra.Command{
		Use:   "certificate",
		Short: "Operations on cert-manager Certificates",
		Long:  `Operations on cert-manager Certificates, e.g. status`,
	}

	cmds.AddCommand(status.NewCmdCertStatus(ioStreams, factory))

	return cmds
}
