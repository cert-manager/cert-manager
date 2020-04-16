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

package renew

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

// Options is a struct to support version command
type Options struct {
	// The Namespace that the Certificate to be renewed resided in
	Namespace string

	LabelSelector string

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdRenew returns a cobra command for renewing Certificates
func NewCmdRenew(ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Mark a Certificate for manual renewal",
		Long:  "Mark a Certificate for manual renewal",
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(factory, cmd, args))
			cmdutil.CheckErr(o.Validate(cmd, args))
			cmdutil.CheckErr(o.Run(factory, cmd, args))
		},
	}

	cmd.Flags().StringVarP(&o.LabelSelector, "selector", "l", o.LabelSelector, "Selector (label query) to filter on, supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)")

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(cmd *cobra.Command, args []string) error {
	if len(o.LabelSelector) > 0 && len(args) > 0 {
		return errors.New("cannot specify Certificate arguments as well as label selectors")
	}

	return nil
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete(f cmdutil.Factory, cmd *cobra.Command, args []string) error {
	var err error
	o.Namespace, _, err = f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	return nil
}

// Run executes version command
func (o *Options) Run(f cmdutil.Factory, cmd *cobra.Command, args []string) error {
	restConfig, err := f.ToRESTConfig()
	if err != nil {
		return err
	}

	cmClient, err := cmclient.NewForConfig(restConfig)
	if err != nil {
		return err
	}

	var crts []cmapi.Certificate

	if len(o.LabelSelector) > 0 {
		crtsList, err := cmClient.CertmanagerV1alpha2().Certificates(o.Namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: o.LabelSelector,
		})
		if err != nil {
			return err
		}

		crts = crtsList.Items

	} else {
		for _, crtName := range args {
			crt, err := cmClient.CertmanagerV1alpha2().Certificates(o.Namespace).Get(context.TODO(), crtName, metav1.GetOptions{})
			if err != nil {
				return err
			}

			crts = append(crts, *crt)
		}
	}

	if len(crts) == 0 {
		return errors.New("No resources found")
	}

	for _, crt := range crts {
		if err := o.renewCertificate(cmClient, &crt); err != nil {
			return err
		}
	}

	return nil
}

func (o *Options) renewCertificate(cmClient *cmclient.Clientset, crt *cmapi.Certificate) error {
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "ManuallyTriggered", "Certificate re-issuance manually triggered")
	_, err := cmClient.CertmanagerV1alpha2().Certificates(crt.Namespace).UpdateStatus(context.TODO(), crt, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to trigger issuance of Certificate %s/%s: %v", crt.Namespace, crt.Name, err)
	}
	fmt.Fprintf(o.Out, "Manually triggered issuance of Certificate %s/%s\n", crt.Namespace, crt.Name)
	return nil
}
