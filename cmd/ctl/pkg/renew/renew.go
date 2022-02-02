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

package renew

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
)

var (
	long = templates.LongDesc(i18n.T(`
Mark cert-manager Certificate resources for manual renewal.`))

	example = templates.Examples(i18n.T(build.WithTemplate(`
# Renew the Certificates named 'my-app' and 'vault' in the current context namespace.
{{.BuildName}} renew my-app vault

# Renew all Certificates in the 'kube-system' namespace.
{{.BuildName}} renew --namespace kube-system --all

# Renew all Certificates in all namespaces, provided those Certificates have the label 'app=my-service'
{{.BuildName}} renew --all-namespaces -l app=my-service`)))
)

// Options is a struct to support renew command
type Options struct {
	LabelSelector string
	All           bool
	AllNamespaces bool

	genericclioptions.IOStreams
	*factory.Factory
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdRenew returns a cobra command for renewing Certificates
func NewCmdRenew(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:               "renew",
		Short:             "Mark a Certificate for manual renewal",
		Long:              long,
		Example:           example,
		ValidArgsFunction: factory.ValidArgsListCertificates(ctx, &o.Factory),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(cmd, args))
			cmdutil.CheckErr(o.Run(ctx, args))
		},
	}

	cmd.Flags().StringVarP(&o.LabelSelector, "selector", "l", o.LabelSelector, "Selector (label query) to filter on, supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)")
	cmd.Flags().BoolVarP(&o.AllNamespaces, "all-namespaces", "A", o.AllNamespaces, "If present, mark Certificates across namespaces for manual renewal. Namespace in current context is ignored even if specified with --namespace.")
	cmd.Flags().BoolVar(&o.All, "all", o.All, "Renew all Certificates in the given Namespace, or all namespaces with --all-namespaces enabled.")

	o.Factory = factory.New(ctx, cmd)

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(cmd *cobra.Command, args []string) error {
	if len(o.LabelSelector) > 0 && len(args) > 0 {
		return errors.New("cannot specify Certificate names in conjunction with label selectors")
	}

	if len(o.LabelSelector) > 0 && o.All {
		return errors.New("cannot specify label selectors in conjunction with --all flag")
	}

	if o.All && len(args) > 0 {
		return errors.New("cannot specify Certificate names in conjunction with --all flag")
	}

	if o.All && cmd.PersistentFlags().Changed("namespace") {
		return errors.New("cannot specify --namespace flag in conjunction with --all flag")
	}

	return nil
}

// Complete takes the command arguments and factory and infers any remaining options.
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

// Run executes renew command
func (o *Options) Run(ctx context.Context, args []string) error {

	nss := []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: o.Namespace}}}

	if o.AllNamespaces {
		kubeClient, err := kubernetes.NewForConfig(o.RESTConfig)
		if err != nil {
			return err
		}

		nsList, err := kubeClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		nss = nsList.Items
	}

	var crts []cmapi.Certificate
	for _, ns := range nss {
		switch {
		case o.All, len(o.LabelSelector) > 0:
			crtsList, err := o.CMClient.CertmanagerV1().Certificates(ns.Name).List(ctx, metav1.ListOptions{
				LabelSelector: o.LabelSelector,
			})
			if err != nil {
				return err
			}

			crts = append(crts, crtsList.Items...)

		default:
			for _, crtName := range args {
				crt, err := o.CMClient.CertmanagerV1().Certificates(ns.Name).Get(ctx, crtName, metav1.GetOptions{})
				if err != nil {
					return err
				}

				crts = append(crts, *crt)
			}
		}
	}

	if len(crts) == 0 {
		if o.AllNamespaces {
			fmt.Fprintln(o.ErrOut, "No Certificates found")
		} else {
			fmt.Fprintf(o.ErrOut, "No Certificates found in %s namespace.\n", o.Namespace)
		}

		return nil
	}

	for _, crt := range crts {
		if err := o.renewCertificate(ctx, &crt); err != nil {
			return err
		}
	}

	return nil
}

func (o *Options) renewCertificate(ctx context.Context, crt *cmapi.Certificate) error {
	apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "ManuallyTriggered", "Certificate re-issuance manually triggered")
	_, err := o.CMClient.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to trigger issuance of Certificate %s/%s: %v", crt.Namespace, crt.Name, err)
	}
	fmt.Fprintf(o.Out, "Manually triggered issuance of Certificate %s/%s\n", crt.Namespace, crt.Name)
	return nil
}
