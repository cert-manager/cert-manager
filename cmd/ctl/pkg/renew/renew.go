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
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

// Options is a struct to support renew command
type Options struct {
	// The Namespace that the Certificate to be renewed resided in
	Namespace string

	LabelSelector string

	All  bool
	Wait bool

	AllNamespaces bool

	PollTime time.Duration
	Timeout  time.Duration

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
	cmd.Flags().BoolVarP(&o.AllNamespaces, "all-namespaces", "A", o.AllNamespaces, "If present, wait for Certificates across all namespaces to become ready. Namespace in current context is ignored even if specified with --namespace.")
	cmd.Flags().BoolVar(&o.All, "all", o.All, "Renew all Certificates in the given Namespace, or all namespaces with --all-namespaces enabled.")
	cmd.Flags().BoolVarP(&o.Wait, "wait", "w", o.Wait, "Wait for all Certificates to become ready once being marked for renewal.")
	cmd.Flags().DurationVar(&o.PollTime, "poll-time", time.Second*2, "Poll period between checking Certificates to become ready. Used in conjunction with --wait.")
	cmd.Flags().DurationVar(&o.Timeout, "timeout", 0, "The length of time to wait before ending watch, zero means never. Any other values should contain a corresponding time unit (e.g. 1s, 2m, 3h).")

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(cmd *cobra.Command, args []string) error {
	if len(o.LabelSelector) > 0 && len(args) > 0 {
		return errors.New("cannot specify Certificate arguments as well as label selectors")
	}

	if o.All && len(args) > 0 {
		return errors.New("cannot specify Certificate arguments as well as --all flag")
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

// Run executes renew command
func (o *Options) Run(f cmdutil.Factory, cmd *cobra.Command, args []string) error {
	restConfig, err := f.ToRESTConfig()
	if err != nil {
		return err
	}

	cmClient, err := cmclient.NewForConfig(restConfig)
	if err != nil {
		return err
	}

	nss := []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: o.Namespace}}}

	// TODO: handle network context

	if o.AllNamespaces {
		kubeClient, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			return err
		}

		nsList, err := kubeClient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return err
		}

		nss = nsList.Items
	}

	var crts []cmapi.Certificate
	for _, ns := range nss {
		switch {
		case o.All, len(o.LabelSelector) > 0:
			crtsList, err := cmClient.CertmanagerV1alpha2().Certificates(ns.Name).List(context.TODO(), metav1.ListOptions{
				LabelSelector: o.LabelSelector,
			})
			if err != nil {
				return err
			}

			crts = append(crts, crtsList.Items...)

		default:
			for _, crtName := range args {
				crt, err := cmClient.CertmanagerV1alpha2().Certificates(ns.Name).Get(context.TODO(), crtName, metav1.GetOptions{})
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
		if err := o.renewCertificate(cmClient, &crt); err != nil {
			return err
		}
	}

	if o.Wait {
		if err := o.waitCertificatesReady(cmClient, crts); err != nil {
			return err
		}

		fmt.Fprintf(o.Out, "%d Certificates successfully renewed\n", len(crts))
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

func (o *Options) waitCertificatesReady(cmClient *cmclient.Clientset, crts []cmapi.Certificate) error {
	// TODO: start poll time after all get requests?
	ticker := time.NewTicker(o.PollTime)
	defer ticker.Stop()

	ctx := context.TODO()

	if o.Timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}

	for {
		lenReady := 0

		for _, crt := range crts {
			crt, err := cmClient.CertmanagerV1alpha2().Certificates(crt.Namespace).Get(context.TODO(), crt.Name, metav1.GetOptions{})
			if err != nil {
				// TODO: handle certificate no longer existing?
				return err
			}

			if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond != nil && cond.Status == cmmeta.ConditionTrue {
				continue
			}

			if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionReady); cond != nil && cond.Status == cmmeta.ConditionTrue {
				lenReady++
			}
		}

		if lenReady == len(crts) {
			return nil
		}

		fmt.Fprintf(o.Out, "Currently %d Certificates out of %d are ready...\n", lenReady, len(crts))

		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
			return fmt.Errorf("%d Certificates failed to become ready in time", len(crts)-lenReady)
		}
	}
}
