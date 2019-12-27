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
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

var requestCmd = &cobra.Command{
	Use:     "request",
	Short:   "Request opertions on cert-manager.",
	Aliases: []string{"req"},
}

func requestIssuerFlags(store *cmmeta.ObjectReference, fs *pflag.FlagSet) {
	fs.StringVar(
		&store.Name,
		"issuer-name",
		"",
		"The target issuer name to issuer the certificate.",
	)

	fs.StringVar(
		&store.Kind,
		"issuer-kind",
		"Issuer",
		"The target issuer kind to sign the certificate.",
	)

	fs.StringVar(
		&store.Group,
		"issuer-group",
		certmanager.GroupName,
		"The target API group name the issuer belongs to",
	)
}

func requestCRSpecFlags(store *v1alpha1.CertificateRequestSpec, fs *pflag.FlagSet) {
	fs.StringVar(
		&store.Duration,
		"duration",
		cmapi.DefaultCertificateDuration.String(),
		"The requested duration the certificate will be valid for.",
	)

	fs.BoolVar(
		&store.IsCA,
		"is-ca",
		false,
		"The signed certifcate will be marked as a CA.",
	)

	fs.StringVarP(
		&store.OutputFile,
		"out",
		"o",
		"/etc/cert-manager/cert.pem",
		"The output file location to store the signed certificate. If empty, output to Stdout.",
	)
}

func requestObjectFlags(store *metav1.ObjectMeta, fs *pflag.FlagSet) {
	fs.StringVar(
		&store.Name,
		"name",
		"",
		"The name of the CertificateRequest Created. If empty it will be generated "+
			"as 'cert-managerctl-*'",
	)

	fs.StringVarP(
		&store.Namespace,
		"namespace",
		"n",
		"",
		"The namespace of the CertificateRequest Created.",
	)
}

func requestCertFlags(fs *pflag.FlagSet) {
	if flags.Request.Certificate == nil {
		flags.Request.Certificate = new(v1alpha1.RequestCertificate)
	}
	store := flags.Request.Certificate

	fs.StringVar(
		&store.CommonName,
		"common-name",
		"",
		"Common name of the signed certificate. If empty, the first element of dns names will be used.",
	)

	fs.StringSliceVar(
		&store.Organizations,
		"organisation",
		[]string{},
		"List of organisations of the signed certificate.",
	)

	fs.StringSliceVar(
		&store.DNSNames,
		"dns-names",
		[]string{},
		"List of DNS names the certificate will be valid for.",
	)

	fs.StringSliceVar(
		&store.IPAddresses,
		"ips",
		[]string{},
		"List of IPs the certificate will be valid for.",
	)

	fs.StringSliceVar(
		&store.URISANs,
		"uris",
		[]string{},
		"List of URIs the certificate will be valid for.",
	)

	fs.StringVar(
		&store.Key,
		"key",
		"/etc/cert-manager/key.pem",
		"The input key file location used to generate the CSR. If file is empty, an "+
			"RSA 2048 private key will be generated and stored at this location",
	)
}

func requestSignFlags(fs *pflag.FlagSet) {
	if flags.Request.Sign == nil {
		flags.Request.Sign = new(v1alpha1.RequestSign)
	}
	store := flags.Request.Sign

	fs.StringVar(
		&store.CSRPEM,
		"csr",
		"",
		"Path location to the CSR PEM to be signed.",
	)
}

func init() {
	pfs := requestCmd.PersistentFlags()
	requestObjectFlags(&flags.Request.ObjectMeta, pfs)
	requestCRSpecFlags(&flags.Request.CertificateRequestSpec, pfs)
	requestIssuerFlags(&flags.Request.IssuerRef, pfs)

	rootCmd.AddCommand(requestCmd)
}
