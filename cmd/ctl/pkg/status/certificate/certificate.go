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
	"context"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	restclient "k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
	"time"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

var (
	long = templates.LongDesc(i18n.T(`
Get details about the current status of a Certificate, including information on related resources like CertificateRequest or Order.`))

	example = templates.Examples(i18n.T(`
# Query status of cert-manager Certificate resource with name my-cert in namespace default
kubectl cert-manager status certificate my-cert --namespace default
`))
)

// Options is a struct to support status certificate command
type Options struct {
	CMClient   cmclient.Interface
	RESTConfig *restclient.Config
	// The Namespace that the Certificate to be renewed resides in.
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

// NewCmdStatusCert returns a cobra command for status certificate
func NewCmdStatusCert(ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "certificate",
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
		return errors.New("the name of the Certificate has to be provided as argument")
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

// Run executes status certificate command
func (o *Options) Run(args []string) error {
	ctx := context.TODO()
	crtName := args[0]

	crt, err := o.CMClient.CertmanagerV1alpha2().Certificates(o.Namespace).Get(ctx, crtName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error when getting Certificate resource: %v", err)
	}

	fmt.Fprintf(o.Out, fmt.Sprintf("Name: %s\nNamespace: %s\n", crt.Name, crt.Namespace))

	// Get necessary info from Certificate
	// Output one line about each type of Condition that is set.
	conditionMsg := ""
	for _, con := range crt.Status.Conditions {
		conditionMsg += fmt.Sprintf("  %s: %s, Reason: %s, Message: %s\n", con.Type, con.Status, con.Reason, con.Message)
	}
	if conditionMsg == "" {
		conditionMsg = "  No Conditions set\n"
	}
	fmt.Fprintf(o.Out, fmt.Sprintf("Conditions:\n%s", conditionMsg))

	// TODO: Get CR from certificate if exists. I think I can just look for it without caring what condition is
	// What about timing issues? When I query condition it's not ready yet, but then looking for crn it's finished and deleted

	dnsNames := formatStringSlice(crt.Spec.DNSNames)
	fmt.Fprintf(o.Out, fmt.Sprintf("DNS Names:\n%s", dnsNames))

	issuerFormat := `Issuer:
  Name: %s
  Kind: %s`
	fmt.Fprintf(o.Out, fmt.Sprintf(issuerFormat+"\n", crt.Spec.IssuerRef.Name, crt.Spec.IssuerRef.Kind))

	fmt.Fprintf(o.Out, fmt.Sprintf("Secret Name: %s\n", crt.Spec.SecretName))

	fmt.Fprintf(o.Out, fmt.Sprintf("Not Before: %s\n", formatTimeString(crt.Status.NotBefore)))
	fmt.Fprintf(o.Out, fmt.Sprintf("Not After: %s\n", formatTimeString(crt.Status.NotAfter)))
	fmt.Fprintf(o.Out, fmt.Sprintf("Renewal Time: %s\n", formatTimeString(crt.Status.RenewalTime)))

	// TODO: print information about secret
	return nil
}

func formatStringSlice(strings []string) string {
	result := ""
	for _, string := range strings {
		result += "- " + string + "\n"
	}
	return result
}

func formatTimeString(t *metav1.Time) string {
	if t != nil {
		return t.Time.Format(time.RFC3339)
	}
	return "<none>"
}
