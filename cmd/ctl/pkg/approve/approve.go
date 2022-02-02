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
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

var (
	example = templates.Examples(i18n.T(build.WithTemplate(`
# Approve a CertificateRequest with the name 'my-cr'
{{.BuildName}} approve my-cr

# Approve a CertificateRequest in namespace default
{{.BuildName}} approve my-cr --namespace default

# Approve a CertificateRequest giving a custom reason and message
{{.BuildName}} approve my-cr --reason "ManualApproval" --reason "Approved by PKI department"
`)))
)

// Options is a struct to support create certificaterequest command
type Options struct {
	// Reason is the string that will be set on the Reason field of the Approved
	// condition.
	Reason string
	// Message is the string that will be set on the Message field of the
	// Approved condition.
	Message string

	genericclioptions.IOStreams
	*factory.Factory
}

// newOptions returns initialized Options
func newOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

func NewCmdApprove(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := newOptions(ioStreams)

	cmd := &cobra.Command{
		Use:               "approve",
		Short:             "Approve a CertificateRequest",
		Long:              `Mark a CertificateRequest as Approved, so it may be signed by a configured Issuer.`,
		Example:           example,
		ValidArgsFunction: factory.ValidArgsListCertificateRequests(ctx, &o.Factory),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Run(ctx, args))
		},
	}

	cmd.Flags().StringVar(&o.Reason, "reason", "KubectlCertManager",
		"The reason to give as to what approved this CertificateRequest.")
	cmd.Flags().StringVar(&o.Message, "message", fmt.Sprintf("manually approved by %q", build.Name()),
		"The message to give as to why this CertificateRequest was approved.")

	o.Factory = factory.New(ctx, cmd)

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

// Run executes approve command
func (o *Options) Run(ctx context.Context, args []string) error {
	cr, err := o.CMClient.CertmanagerV1().CertificateRequests(o.Namespace).Get(ctx, args[0], metav1.GetOptions{})
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

	_, err = o.CMClient.CertmanagerV1().CertificateRequests(o.Namespace).UpdateStatus(ctx, cr, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	fmt.Fprintf(o.Out, "Approved CertificateRequest '%s/%s'\n", cr.Namespace, cr.Name)

	return nil
}
