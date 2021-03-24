/*
Copyright 2021 The cert-manager Authors.

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

package approve

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

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

var (
	example = templates.Examples(i18n.T(`
# Approve a CertificateRequest with the name 'my-cr'
kubectl cert-manager approve my-cr

# Approve a CertificateRequest in namespace default
kubectl cert-manager approve my-cr --namespace default

# Approve a CertificateRequest giving a custom reason and message
kubectl cert-manager approve my-cr --reason "ManualApproval" --reason "Approved by PKI department"
`))
)

// Options is a struct to support create certificaterequest command
type Options struct {
	CMClient   cmclient.Interface
	RESTConfig *restclient.Config
	// Namespace resulting from the merged result of all overrides
	// since namespace can be specified in file, as flag and in kube config
	CmdNamespace string
	// boolean indicating if there was an Override in determining CmdNamespace
	EnforceNamespace bool

	// Reason is the string that will be set on the Reason field of the Approved
	// condition.
	Reason string
	// Message is the string that will be set on the Message field of the
	// Approved condition.
	Message string

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

func NewCmdApprove(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "approve",
		Short:   "Approve a CertificateRequest",
		Long:    `Mark a CertificateRequest as Approved, so it may be signed by a configured Issuer.`,
		Example: example,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Complete(factory))
			cmdutil.CheckErr(o.Run(ctx, args))
		},
	}

	cmd.Flags().StringVar(&o.Reason, "reason", "KubectlCertManager",
		"The reason to give as to what approved this CertificateRequest.")
	cmd.Flags().StringVar(&o.Message, "message", `manually approved by "kubectl cert-manager"`,
		"The message to give as to why this CertificateRequest was approved.")

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(args []string) error {
	if len(args) < 1 {
		return errors.New("the name of the CertificateRequest to approve has to be provided as an argument")
	}
	if len(args) > 1 {
		return errors.New("only one argument can be passed: the name of the CertificateRequest")
	}

	if len(o.Reason) == 0 {
		return errors.New("a reason must be given as to who approved this CertificateRequest")
	}

	if len(o.Message) == 0 {
		return errors.New("a message must be given as to why this CertificateRequest is approved")
	}

	return nil
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete(f cmdutil.Factory) error {
	var err error

	o.CmdNamespace, o.EnforceNamespace, err = f.ToRawKubeConfigLoader().Namespace()
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

// Run executes create certificaterequest command
func (o *Options) Run(ctx context.Context, args []string) error {
	cr, err := o.CMClient.CertmanagerV1().CertificateRequests(o.CmdNamespace).Get(ctx, args[0], metav1.GetOptions{})
	if err != nil {
		return err
	}

	if apiutil.CertificateRequestIsApproved(cr) {
		return errors.New("CertificateRequest is already approved")
	}

	if apiutil.CertificateRequestIsDenied(cr) {
		return errors.New("CertificateRequest is already denied")
	}

	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved,
		cmmeta.ConditionTrue, o.Reason, o.Message)

	_, err = o.CMClient.CertmanagerV1().CertificateRequests(o.CmdNamespace).UpdateStatus(ctx, cr, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	fmt.Fprintf(o.Out, "Approved CertificateRequest '%s/%s'\n", cr.Namespace, cr.Name)

	return nil
}
