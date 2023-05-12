/*
Copyright 2020 The cert-manager Authors.

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
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/reference"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/cert-manager/cert-manager/pkg/ctl"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
)

var (
	long = templates.LongDesc(i18n.T(`
Get details about the current status of a cert-manager Certificate resource, including information on related resources like CertificateRequest or Order.`))

	example = templates.Examples(i18n.T(build.WithTemplate(`
# Query status of Certificate with name 'my-crt' in namespace 'my-namespace'
{{.BuildName}} status certificate my-crt --namespace my-namespace
`)))
)

// Options is a struct to support status certificate command
type Options struct {
	genericclioptions.IOStreams
	*factory.Factory
}

// Data is a struct containing the information to build a CertificateStatus
type Data struct {
	Certificate  *cmapi.Certificate
	CrtEvents    *corev1.EventList
	Issuer       cmapi.GenericIssuer
	IssuerKind   string
	IssuerError  error
	IssuerEvents *corev1.EventList
	Secret       *corev1.Secret
	SecretError  error
	SecretEvents *corev1.EventList
	Req          *cmapi.CertificateRequest
	ReqError     error
	ReqEvents    *corev1.EventList
	Order        *cmacme.Order
	OrderError   error
	Challenges   []*cmacme.Challenge
	ChallengeErr error
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdStatusCert returns a cobra command for status certificate
func NewCmdStatusCert(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:               "certificate",
		Short:             "Get details about the current status of a cert-manager Certificate resource",
		Long:              long,
		Example:           example,
		ValidArgsFunction: factory.ValidArgsListCertificates(ctx, &o.Factory),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Run(ctx, args))
		},
	}

	o.Factory = factory.New(ctx, cmd)

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

// Run executes status certificate command
func (o *Options) Run(ctx context.Context, args []string) error {
	data, err := o.GetResources(ctx, args[0])
	if err != nil {
		return err
	}

	// Build status of Certificate with data gathered
	status := StatusFromResources(data)

	fmt.Fprintf(o.Out, status.String())

	return nil
}

// GetResources collects all related resources of the Certificate and any errors while doing so
// in a Data struct and returns it.
// Returns error if error occurs when finding Certificate resource or while preparing to find other resources,
// e.g. when creating clientSet
func (o *Options) GetResources(ctx context.Context, crtName string) (*Data, error) {
	clientSet, err := kubernetes.NewForConfig(o.RESTConfig)
	if err != nil {
		return nil, err
	}

	crt, err := o.CMClient.CertmanagerV1().Certificates(o.Namespace).Get(ctx, crtName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when getting Certificate resource: %v", err)
	}

	crtRef, err := reference.GetReference(ctl.Scheme, crt)
	if err != nil {
		return nil, err
	}
	// If no events found, crtEvents would be nil and handled down the line in DescribeEvents
	crtEvents, err := clientSet.CoreV1().Events(crt.Namespace).Search(ctl.Scheme, crtRef)
	if err != nil {
		return nil, err
	}

	issuer, issuerKind, issuerError := getGenericIssuer(o.CMClient, ctx, crt)
	var issuerEvents *corev1.EventList
	if issuer != nil {
		issuerRef, err := reference.GetReference(ctl.Scheme, issuer)
		if err != nil {
			return nil, err
		}
		// If no events found, issuerEvents would be nil and handled down the line in DescribeEvents
		issuerEvents, err = clientSet.CoreV1().Events(issuer.GetNamespace()).Search(ctl.Scheme, issuerRef)
		if err != nil {
			return nil, err
		}
	}

	secret, secretErr := clientSet.CoreV1().Secrets(crt.Namespace).Get(ctx, crt.Spec.SecretName, metav1.GetOptions{})
	if secretErr != nil {
		secretErr = fmt.Errorf("error when finding Secret %q: %w\n", crt.Spec.SecretName, secretErr)
	}
	var secretEvents *corev1.EventList
	if secret != nil {
		secretRef, err := reference.GetReference(ctl.Scheme, secret)
		if err != nil {
			return nil, err
		}
		// If no events found, secretEvents would be nil and handled down the line in DescribeEvents
		secretEvents, err = clientSet.CoreV1().Events(secret.Namespace).Search(ctl.Scheme, secretRef)
		if err != nil {
			return nil, err
		}
	}

	// TODO: What about timing issues? When I query condition it's not ready yet, but then looking for cr it's finished and deleted
	// Try find the CertificateRequest that is owned by crt and has the correct revision
	req, reqErr := findMatchingCR(o.CMClient, ctx, crt)
	if reqErr != nil {
		reqErr = fmt.Errorf("error when finding CertificateRequest: %w\n", reqErr)
	} else if req == nil {
		reqErr = errors.New("No CertificateRequest found for this Certificate\n")
	}

	var reqEvents *corev1.EventList
	if req != nil {
		reqRef, err := reference.GetReference(ctl.Scheme, req)
		if err != nil {
			return nil, err
		}
		// If no events found,  reqEvents would be nil and handled down the line in DescribeEvents
		reqEvents, err = clientSet.CoreV1().Events(req.Namespace).Search(ctl.Scheme, reqRef)
		if err != nil {
			return nil, err
		}
	}

	var (
		order        *cmacme.Order
		orderErr     error
		challenges   []*cmacme.Challenge
		challengeErr error
	)

	// Nothing to output about Order and Challenge if no CR or not ACME Issuer
	if req != nil && issuer != nil && issuer.GetSpec().ACME != nil {
		// Get Order
		order, orderErr = findMatchingOrder(o.CMClient, ctx, req)
		if orderErr != nil {
			orderErr = fmt.Errorf("error when finding Order: %w\n", orderErr)
		} else if order == nil {
			orderErr = errors.New("No Order found for this Certificate\n")
		}

		if order != nil {
			challenges, challengeErr = findMatchingChallenges(o.CMClient, ctx, order)
			if challengeErr != nil {
				challengeErr = fmt.Errorf("error when finding Challenges: %w\n", challengeErr)
			} else if len(challenges) == 0 {
				challengeErr = errors.New("No Challenges found for this Certificate\n")
			}
		}
	}

	return &Data{
		Certificate:  crt,
		CrtEvents:    crtEvents,
		Issuer:       issuer,
		IssuerKind:   issuerKind,
		IssuerError:  issuerError,
		IssuerEvents: issuerEvents,
		Secret:       secret,
		SecretError:  secretErr,
		SecretEvents: secretEvents,
		Req:          req,
		ReqError:     reqErr,
		ReqEvents:    reqEvents,
		Order:        order,
		OrderError:   orderErr,
		Challenges:   challenges,
		ChallengeErr: challengeErr,
	}, nil
}

// StatusFromResources takes in a Data struct and returns a CertificateStatus built using
// the information in data.
func StatusFromResources(data *Data) *CertificateStatus {
	return newCertificateStatusFromCert(data.Certificate).
		withEvents(data.CrtEvents).
		withGenericIssuer(data.Issuer, data.IssuerKind, data.IssuerEvents, data.IssuerError).
		withSecret(data.Secret, data.SecretEvents, data.SecretError).
		withCR(data.Req, data.ReqEvents, data.ReqError).
		withOrder(data.Order, data.OrderError).
		withChallenges(data.Challenges, data.ChallengeErr)
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
// If multiple found or error occurs when listing CRs, returns error
func findMatchingCR(cmClient cmclient.Interface, ctx context.Context, crt *cmapi.Certificate) (*cmapi.CertificateRequest, error) {
	reqs, err := cmClient.CertmanagerV1().CertificateRequests(crt.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when listing CertificateRequest resources: %w", err)
	}

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

// findMatchingOrder tries to find an Order that is owned by req.
// If none found returns nil
// If one found returns the Order
// If multiple found or error occurs when listing Orders, returns error
func findMatchingOrder(cmClient cmclient.Interface, ctx context.Context, req *cmapi.CertificateRequest) (*cmacme.Order, error) {
	orders, err := cmClient.AcmeV1().Orders(req.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	possibleMatches := []*cmacme.Order{}
	for _, order := range orders.Items {
		if predicate.ResourceOwnedBy(req)(&order) {
			possibleMatches = append(possibleMatches, order.DeepCopy())
		}
	}

	if len(possibleMatches) < 1 {
		return nil, nil
	} else if len(possibleMatches) == 1 {
		return possibleMatches[0], nil
	} else {
		return nil, fmt.Errorf("found multiple orders owned by CertificateRequest %s", req.Name)
	}
}

func getGenericIssuer(cmClient cmclient.Interface, ctx context.Context, crt *cmapi.Certificate) (cmapi.GenericIssuer, string, error) {
	issuerKind := crt.Spec.IssuerRef.Kind
	if issuerKind == "" {
		issuerKind = "Issuer"
	}

	if crt.Spec.IssuerRef.Group != "cert-manager.io" && crt.Spec.IssuerRef.Group != "" {
		// TODO: Support Issuers/ClusterIssuers from other groups as well
		return nil, "", fmt.Errorf("The %s %q is not of the group cert-manager.io, this command currently does not support third party issuers.\nTo get more information about %q, try 'kubectl describe'\n",
			issuerKind, crt.Spec.IssuerRef.Name, crt.Spec.IssuerRef.Name)
	} else if issuerKind == "Issuer" {
		issuer, issuerErr := cmClient.CertmanagerV1().Issuers(crt.Namespace).Get(ctx, crt.Spec.IssuerRef.Name, metav1.GetOptions{})
		if issuerErr != nil {
			issuerErr = fmt.Errorf("error when getting Issuer: %v\n", issuerErr)
		}
		return issuer, issuerKind, issuerErr
	} else {
		// ClusterIssuer
		clusterIssuer, issuerErr := cmClient.CertmanagerV1().ClusterIssuers().Get(ctx, crt.Spec.IssuerRef.Name, metav1.GetOptions{})
		if issuerErr != nil {
			issuerErr = fmt.Errorf("error when getting ClusterIssuer: %v\n", issuerErr)
		}
		return clusterIssuer, issuerKind, issuerErr
	}
}

// findMatchingChallenges tries to find Challenges that are owned by order.
// If none found returns empty slice.
func findMatchingChallenges(cmClient cmclient.Interface, ctx context.Context, order *cmacme.Order) ([]*cmacme.Challenge, error) {
	challenges, err := cmClient.AcmeV1().Challenges(order.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	possibleMatches := []*cmacme.Challenge{}
	for _, challenge := range challenges.Items {
		if predicate.ResourceOwnedBy(order)(&challenge) {
			possibleMatches = append(possibleMatches, challenge.DeepCopy())
		}
	}

	return possibleMatches, nil
}
