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
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubectl/pkg/describe"
	"strings"
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

	fmt.Fprintf(o.Out, "Name: %s\nNamespace: %s\n", crt.Name, crt.Namespace)

	fmt.Fprintf(o.Out, fmt.Sprintf("Created at: %s\n", crt.CreationTimestamp.Time.Format(time.RFC3339)))

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
	fmt.Fprintf(o.Out, "Conditions:\n%s", conditionMsg)

	dnsNames := formatStringSlice(crt.Spec.DNSNames)
	fmt.Fprintf(o.Out, "DNS Names:\n%s", dnsNames)

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

	issuerKind := crt.Spec.IssuerRef.Kind
	if issuerKind == "" {
		issuerKind = "Issuer"
	}

	// Get info on Issuer/ClusterIssuer
	if crt.Spec.IssuerRef.Group != "cert-manager.io" && crt.Spec.IssuerRef.Group != "" {
		// TODO: Support Issuers/ClusterIssuers from other groups as well
		fmt.Fprintf(o.Out, "The %s %q is not of the group cert-manager.io, this command currently does not support third party issuers.\nTo get more information about %q, try 'kubectl describe'\n",
			issuerKind, crt.Spec.IssuerRef.Name, crt.Spec.IssuerRef.Name)
	} else if issuerKind == "Issuer" {
		issuer, err := o.CMClient.CertmanagerV1alpha2().Issuers(crt.Namespace).Get(ctx, crt.Spec.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			fmt.Fprintf(o.Out, "error when getting Issuer: %v\n", err)
		} else {
			fmt.Fprintf(o.Out, issuerInfoString(crt.Spec.IssuerRef.Name, issuerKind, issuer.Status.Conditions))
		}
	} else {
		// ClusterIssuer
		clusterIssuer, err := o.CMClient.CertmanagerV1alpha2().ClusterIssuers().Get(ctx, crt.Spec.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			fmt.Fprintf(o.Out, "error when getting ClusterIssuer: %v\n", err)
		} else {
			fmt.Fprintf(o.Out, issuerInfoString(crt.Spec.IssuerRef.Name, issuerKind, clusterIssuer.Status.Conditions))
		}
	}

	secret, err := clientSet.CoreV1().Secrets(o.Namespace).Get(ctx, crt.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		fmt.Fprintf(o.Out, "error when finding secret %q: %s\n", crt.Spec.SecretName, err)
	} else {
		fmt.Fprintf(o.Out, secretInfoString(secret))
	}

	fmt.Fprintf(o.Out, "Not Before: %s\n", formatTimeString(crt.Status.NotBefore))
	fmt.Fprintf(o.Out, "Not After: %s\n", formatTimeString(crt.Status.NotAfter))
	fmt.Fprintf(o.Out, "Renewal Time: %s\n", formatTimeString(crt.Status.RenewalTime))

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
			possibleMatches = append(possibleMatches, req.DeepCopy())
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

// issuerInfoString returns the information of a issuer as a string to be printed as output
func issuerInfoString(name, kind string, conditions []cmapi.IssuerCondition) string {
	issuerFormat := `Issuer:
  Name: %s
  Kind: %s
  Conditions:
  %s`
	conditionMsg := ""
	for _, con := range conditions {
		conditionMsg += fmt.Sprintf("  %s: %s, Reason: %s, Message: %s\n", con.Type, con.Status, con.Reason, con.Message)
	}
	if conditionMsg == "" {
		conditionMsg = "  No Conditions set\n"
	}
	return fmt.Sprintf(issuerFormat, name, kind, conditionMsg)
}

func secretInfoString(secret *corev1.Secret) string {
	certData := secret.Data["tls.crt"]

	if len(certData) == 0 {
		return fmt.Sprintf("error: 'tls.crt' of Secret %q is not set\n", secret.Name)
	}

	x509Cert, err := pki.DecodeX509CertificateBytes(certData)
	if err != nil {
		return fmt.Sprintf("error when parsing 'tls.crt' of Secret %q: %s\n", secret.Name, err)
	}
	secretFormat := `Secret:
  Name: %s
  Issuer Country: %s
  Issuer Organisation: %s
  Issuer Common Name: %s
  Key Usage: %s
  Extended Key Usages: %s
  Public Key Algorithm: %s
  Signature Algorithm: %s
  Subject Key ID: %s
  Authority Key ID: %s
  Serial Number: %s
`
	return fmt.Sprintf(secretFormat, secret.Name, strings.Join(x509Cert.Issuer.Country, ", "),
		strings.Join(x509Cert.Issuer.Organization, ", "),
		x509Cert.Issuer.CommonName, keyUsageToString(x509Cert.KeyUsage),
		extKeyUsageToString(x509Cert.ExtKeyUsage), x509Cert.PublicKeyAlgorithm, x509Cert.SignatureAlgorithm,
		hex.EncodeToString(x509Cert.SubjectKeyId), hex.EncodeToString(x509Cert.AuthorityKeyId),
		hex.EncodeToString(x509Cert.SerialNumber.Bytes()))
}

var (
	keyUsage = map[int]string{
		1:   "Digital Signature",
		2:   "Content Commitment",
		4:   "Key Encipherment",
		8:   "Data Encipherment",
		16:  "Key Agreement",
		32:  "Cert Sign",
		64:  "CRL Sign",
		128: "Encipher Only",
		256: "Decipher Only",
	}
	keyUsagePossibleValues = []int{256, 128, 64, 32, 16, 8, 4, 2, 1}
	extKeyUsage            = []string{"Any", "Server Authentication", "Client Authentication", "Code Signing", "Email Protection",
		"IPSEC End System", "IPSEC Tunnel", "IPSEC User", "Time Stamping", "OCSP Signing", "Microsoft Server Gated Crypto",
		"Netscape Server Gated Crypto", "Microsoft Commercial Code Signing", "Microsoft Kernel Code Signing",
	}
)

func keyUsageToString(usage x509.KeyUsage) string {
	usageInt := int(usage)
	var usageStrings []string
	for _, val := range keyUsagePossibleValues {
		if usageInt >= val {
			usageInt -= val
			usageStrings = append(usageStrings, keyUsage[val])
		}
		if usageInt == 0 {
			break
		}
	}
	// Reversing because that's usually the order the usages are printed
	for i := 0; i < len(usageStrings)/2; i++ {
		opp := len(usageStrings) - 1 - i
		usageStrings[i], usageStrings[opp] = usageStrings[opp], usageStrings[i]
	}
	return strings.Join(usageStrings, ", ")
}

func extKeyUsageToString(extUsages []x509.ExtKeyUsage) string {
	var extUsageStrings []string
	for _, extUsage := range extUsages {
		extUsageStrings = append(extUsageStrings, extKeyUsage[extUsage])
	}
	return strings.Join(extUsageStrings, ", ")
}
