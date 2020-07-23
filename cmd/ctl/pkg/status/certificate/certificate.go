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
	"k8s.io/kubectl/pkg/describe"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/reference"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/status/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/ctl"
	"github.com/jetstack/cert-manager/pkg/util/predicate"
)

var (
	long = templates.LongDesc(i18n.T(`
Get details about the current status of a cert-manager Certificate resource, including information on related resources like CertificateRequest.`))

	example = templates.Examples(i18n.T(`
# Query status of Certificate with name 'my-crt' in namespace 'my-namespace'
kubectl cert-manager status certificate my-crt --namespace my-namespace
`))
)

// Options is a struct to support status certificate command
type Options struct {
	CMClient   cmclient.Interface
	RESTConfig *restclient.Config
	// The Namespace that the Certificate to be queried about resides in.
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
		Short:   "Get details about the current status of a cert-manager Certificate resource",
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

	clientSet, err := kubernetes.NewForConfig(o.RESTConfig)
	if err != nil {
		return err
	}

	crt, err := o.CMClient.CertmanagerV1alpha2().Certificates(o.Namespace).Get(ctx, crtName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error when getting Certificate resource: %v", err)
	}

	fmt.Fprintf(o.Out, fmt.Sprintf("Name: %s\nNamespace: %s\n", crt.Name, crt.Namespace))

	// Get necessary info from Certificate
	// Output one line about each type of Condition that is set.
	// Certificate can have multiple Conditions of different types set, e.g. "Ready" or "Issuing"
	conditionMsg := ""
	for _, con := range crt.Status.Conditions {
		conditionMsg += fmt.Sprintf("  %s: %s, Reason: %s, Message: %s\n", con.Type, con.Status, con.Reason, con.Message)
	}
	if conditionMsg == "" {
		conditionMsg = "  No Conditions set\n"
	}
	fmt.Fprintf(o.Out, fmt.Sprintf("Conditions:\n%s", conditionMsg))

	dnsNames := formatStringSlice(crt.Spec.DNSNames)
	fmt.Fprintf(o.Out, fmt.Sprintf("DNS Names:\n%s", dnsNames))

	crtRef, err := reference.GetReference(ctl.Scheme, crt)
	if err != nil {
		return err
	}
	// Ignore error, since if there was an error, crtEvents would be nil and handled down the line in DescribeEvents
	crtEvents, _ := clientSet.CoreV1().Events(o.Namespace).Search(ctl.Scheme, crtRef)
	tabWriter := tabwriter.NewWriter(o.Out, 0, 8, 2, ' ', 0)
	prefixWriter := describe.NewPrefixWriter(tabWriter)
	util.DescribeEvents(crtEvents, prefixWriter, 0)
	tabWriter.Flush()

	issuerFormat := `Issuer:
  Name: %s
  Kind: %s`
	issuerKind := crt.Spec.IssuerRef.Kind
	if issuerKind == "" {
		issuerKind = "Issuer"
	}
	fmt.Fprintf(o.Out, fmt.Sprintf(issuerFormat+"\n", crt.Spec.IssuerRef.Name, issuerKind))

	fmt.Fprintf(o.Out, fmt.Sprintf("Secret Name: %s\n", crt.Spec.SecretName))

	fmt.Fprintf(o.Out, fmt.Sprintf("Not Before: %s\n", formatTimeString(crt.Status.NotBefore)))
	fmt.Fprintf(o.Out, fmt.Sprintf("Not After: %s\n", formatTimeString(crt.Status.NotAfter)))
	fmt.Fprintf(o.Out, fmt.Sprintf("Renewal Time: %s\n", formatTimeString(crt.Status.RenewalTime)))

	// TODO: What about timing issues? When I query condition it's not ready yet, but then looking for cr it's finished and deleted
	// Try find the CertificateRequest that is owned by crt and has the correct revision
	reqs, err := o.CMClient.CertmanagerV1alpha2().CertificateRequests(o.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	req, err := findMatchingCR(reqs, crt)
	if err != nil {
		return err
	}
	fmt.Fprintf(o.Out, crInfoString(req))
	if req != nil {
		reqRef, err := reference.GetReference(ctl.Scheme, req)
		if err != nil {
			return err
		}
		// Ignore error, since if there was an error, reqEvents would be nil and handled down the line in DescribeEvents
		reqEvents, _ := clientSet.CoreV1().Events(o.Namespace).Search(ctl.Scheme, reqRef)

		util.DescribeEvents(reqEvents, prefixWriter, 1)
		tabWriter.Flush()
	}

	// TODO: print information about secret
	return nil
}

// formatStringSlice takes in a string slice and formats the contents of the slice
// into a single string where each element of the slice is prefixed with "- " and on a new line
func formatStringSlice(strings []string) string {
	result := ""
	for _, str := range strings {
		result += "- " + str + "\n"
	}
	return result
}

// formatTimeString returns the time as a string
// If nil, return "<none>"
func formatTimeString(t *metav1.Time) string {
	if t == nil {
		return "<none>"
	}
	return t.Time.Format(time.RFC3339)
}

// findMatchingCR tries to find a CertificateRequest that is owned by crt and has the correct revision annotated from reqs.
// If none found returns nil
// If one found returns the CR
// If multiple found returns error
func findMatchingCR(reqs *cmapi.CertificateRequestList, crt *cmapi.Certificate) (*cmapi.CertificateRequest, error) {
	possibleMatches := []*cmapi.CertificateRequest{}

	// CertificateRequest revisions begin from 1.
	// If no revision is set on the Certificate then assume the revision on the CertificateRequest should be 1.
	// If revision is set on the Certificate then revision on the CertificateRequest should be crt.Status.Revision + 1.
	nextRevision := 1
	if crt.Status.Revision != nil {
		nextRevision = *crt.Status.Revision + 1
	}
	for _, req := range reqs.Items {
		if predicate.CertificateRequestRevision(nextRevision)(&req) &&
			predicate.ResourceOwnedBy(crt)(&req) {
			possibleMatches = append(possibleMatches, &req)
		}
	}

	if len(possibleMatches) < 1 {
		return nil, nil
	} else if len(possibleMatches) == 1 {
		return possibleMatches[0], nil
	} else {
		return nil, errors.New("found multiple certificate requests with expected revision and owner")
	}
}

// crInfoString returns the information of a CR as a string to be printed as output
func crInfoString(cr *cmapi.CertificateRequest) string {
	if cr == nil {
		return "No CertificateRequest found for this Certificate\n"
	}

	crFormat := `
  Name: %s
  Namespace: %s
  Conditions:
  %s`
	conditionMsg := ""
	for _, con := range cr.Status.Conditions {
		conditionMsg += fmt.Sprintf("  %s: %s, Reason: %s, Message: %s\n", con.Type, con.Status, con.Reason, con.Message)
	}
	if conditionMsg == "" {
		conditionMsg = "  No Conditions set\n"
	}
	infos := fmt.Sprintf(crFormat, cr.Name, cr.Namespace, conditionMsg)
	return fmt.Sprintf("CertificateRequest:%s", infos)
}
