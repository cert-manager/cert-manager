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
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/apis/cert-managerctl/v1alpha1"
	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/client"
	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/update"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a CertificateRequest with a x509 encoded signed certificate or mark the resource as failed or pending.",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := client.New(flags.Kubeconfig)
		if err != nil {
			return err
		}

		update := update.New(client, &flags.Update)
		mustDie(update.CertificateRequest())

		return nil
	},
}

func updateCertificateRequestFlags(store *v1alpha1.Update, fs *pflag.FlagSet) {
	fs.StringVar(
		&store.CertificatePEM,
		"cert",
		"",
		"Path location to the signed Certificate PEM to update with.",
	)

	fs.StringVar(
		&store.CAPEM,
		"ca",
		"",
		"Path location to the CA PEM to update with.",
	)

	fs.StringVar(
		&store.ReadyConditionReason,
		"reason",
		"Issued",
		`Ready condition reason to set on the CertificateRequest resource status, one of: ["Issued", "Pending", "Failed"]`,
	)

	fs.StringVar(
		&store.ReadyConditionMessage,
		"message",
		"",
		"Ready condition message to set on the CertificateRequest resource status.",
	)
}

func updateObjectFlags(store *metav1.ObjectMeta, fs *pflag.FlagSet) {
	fs.StringVar(
		&store.Name,
		"name",
		"",
		"The name of the CertificateRequest to be Updated",
	)

	fs.StringVarP(
		&store.Namespace,
		"namespace",
		"n",
		"",
		"The namespace of the CertificateRequest to be Updated.",
	)
}

func init() {
	pfs := updateCmd.PersistentFlags()
	updateCertificateRequestFlags(&flags.Update, pfs)
	updateObjectFlags(&flags.Update.ObjectMeta, pfs)

	rootCmd.AddCommand(updateCmd)
}
