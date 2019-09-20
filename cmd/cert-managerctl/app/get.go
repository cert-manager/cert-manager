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
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/apis/cert-managerctl/v1alpha1"
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get cert-manager resources.",
}

func getObjectFlags(store *metav1.ObjectMeta, fs *pflag.FlagSet) {
	fs.StringVar(
		&store.Name,
		"name",
		"",
		"The name of the CertificateRequest storing the certificate.",
	)

	fs.StringVarP(
		&store.Namespace,
		"namespace",
		"n",
		"",
		"The namespace of the CertificateRequest storing the certificate.",
	)
}

func getCertFlags(fs *pflag.FlagSet) {
	if flags.Get.Certificate == nil {
		flags.Get.Certificate = new(v1alpha1.GetCertificate)
	}
	store := flags.Get.Certificate

	fs.StringVarP(
		&store.OutputFile,
		"out",
		"o",
		"",
		"The output file location to store the signed certificate. If empty, output "+
			"to Stdout.",
	)

	fs.BoolVarP(
		&store.Wait,
		"wait",
		"w",
		false,
		"Wait for the target CertificateRequest to become ready",
	)
}

func init() {
	pfs := getCmd.PersistentFlags()
	getObjectFlags(&flags.Get.ObjectMeta, pfs)

	rootCmd.AddCommand(getCmd)
}
