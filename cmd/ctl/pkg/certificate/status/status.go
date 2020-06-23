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
	"context"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	restclient "k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

var (
	long = templates.LongDesc(i18n.T(`
Get details about the current status of a Certificate, including information on related resources like CertificateRequest or Order.`))

	example = templates.Examples(i18n.T(`
`))
)

const (
	readyAndUptoDateFormat = `
Name: %s
Namespace: %s
Status: %s
DNS Names:
%s
Issuer:
  Name: %s
  Kind: %s
Secret Name: %s
Not After: %s
`
)

// Options is a struct to support certificate status command
type Options struct {
	CMClient   cmclient.Interface
	RESTConfig *restclient.Config
	// The Namespace that the Certificate to be renewed resided in.
	// This flag registration is handled by cmdutil.Factory
	Namespace string

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdCertStatus returns a cobra command for create CertificateRequest
func NewCmdCertStatus(ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Get details about the current status of a Certificate",
		Long:    long,
		Example: example,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Complete(factory))
			cmdutil.CheckErr(o.Run(args))
		},
	}
	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(args []string) error {
	if len(args) < 1 {
		return errors.New("the name of the Certificate to be created has to be provided as argument")
	}
	if len(args) > 1 {
		return errors.New("only one argument can be passed in: the name of the Certificate")
	}
	return nil
}

// Complete takes the factory and infers any remaining options.
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

func (o *Options) Run(args []string) error {
	ctx := context.TODO()
	crtName := args[0]

	crt, err := o.CMClient.CertmanagerV1alpha2().Certificates(o.Namespace).Get(ctx, crtName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error when getting Certificate resource: %v", err)
	}

	// Get necessary info from Certificate
	statusMessage := ""
	for i, con := range crt.Status.Conditions {
		// TODO: Can a certificate have both Ready and Issuin
		if i < len(crt.Status.Conditions)-1 {
			statusMessage += con.Message + "; "
		} else {
			statusMessage += con.Message
		}
	}

	dnsNames := formatDnsNamesList(crt)

	fmt.Fprintf(o.Out, readyAndUptoDateFormat, crt.Name, crt.Namespace, statusMessage, dnsNames, crt.Spec.IssuerRef.Name,
		crt.Spec.IssuerRef.Kind, crt.Spec.SecretName, crt.Status.NotAfter.Time.Format(time.RFC3339))
	return nil
}

func formatDnsNamesList(crt *cmapi.Certificate) string {
	str := ""
	for _, dnsName := range crt.Spec.DNSNames {
		str += "- " + dnsName
	}
	return str
}
