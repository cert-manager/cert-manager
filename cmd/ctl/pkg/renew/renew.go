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
	restclient "k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

const (
	// poll time used when waiting for Certificates to become ready
	pollTime = time.Second * 2
)

var (
	long = templates.LongDesc(i18n.T(`
	Mark cert-manager Certificate resources for manual renewal.
`))

	example = templates.Examples(i18n.T(`
		# Renew the Certificates named 'my-app' and 'vault' in the current context namespace and wait until they are ready.
		ctl renew my-app vault --wait

		# Renew all Certificates in the 'kube-system' namespace.
		ctl renew --namespace kube-system --all

		# Renew all Certificates in all namespaces that have the label 'app=my-service'.
		ctl renew --all-namespaces -l app=my-service`))
)

// Options is a struct to support renew command
type Options struct {
	// The Namespace that the Certificate to be renewed resided in
	Namespace  string
	CMClient   cmclient.Interface
	RestConfig *restclient.Config

	LabelSelector string
	All           bool
	Wait          bool
	AllNamespaces bool

	Timeout time.Duration

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
		Use:     "renew",
		Short:   "Mark a Certificate for manual renewal",
		Long:    "Mark a Certificate for manual renewal",
		Example: example,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(factory))
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Run(args))
		},
	}

	cmd.Flags().StringVarP(&o.LabelSelector, "selector", "l", o.LabelSelector, "Selector (label query) to filter on, supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)")
	cmd.Flags().BoolVarP(&o.AllNamespaces, "all-namespaces", "A", o.AllNamespaces, "If present, wait for Certificates across all namespaces to become ready. Namespace in current context is ignored even if specified with --namespace.")
	cmd.Flags().BoolVar(&o.All, "all", o.All, "Renew all Certificates in the given Namespace, or all namespaces with --all-namespaces enabled.")
	cmd.Flags().BoolVarP(&o.Wait, "wait", "w", o.Wait, "Wait for all Certificates to become ready once being marked for renewal.")
	timeoutDescription := fmt.Sprintf("The length of time to wait before ending watch, zero means never. Any other values should contain a corresponding time unit (e.g. 1s, 2m, 3h). Cannot be less than the poll time %s, if not zero", pollTime)
	cmd.Flags().DurationVar(&o.Timeout, "timeout", 0, timeoutDescription)

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(args []string) error {
	if len(o.LabelSelector) > 0 && len(args) > 0 {
		return errors.New("cannot specify Certificate names in conjunction with label selectors")
	}

	if len(o.LabelSelector) > 0 && o.All {
		return errors.New("cannot specify label selectors in conjunction with --all flag")
	}

	if o.All && len(args) > 0 {
		return errors.New("cannot specify Certificate names in conjunction with --all flag")
	}

	// Only validate timeout if we are also waiting
	if o.Wait && o.Timeout != 0 && o.Timeout < pollTime {
		return fmt.Errorf("timeout of %s cannot be less than the poll time of %s if timeout is not zero",
			o.Timeout, pollTime)
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

	o.RestConfig, err = f.ToRESTConfig()
	if err != nil {
		return err
	}

	o.CMClient, err = cmclient.NewForConfig(o.RestConfig)
	if err != nil {
		return err
	}

	return nil
}

// Run executes renew command
func (o *Options) Run(args []string) error {
	ctx := context.TODO()

	nss := []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: o.Namespace}}}

	// TODO: handle network context

	if o.AllNamespaces {
		kubeClient, err := kubernetes.NewForConfig(o.RestConfig)
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
			crtsList, err := o.CMClient.CertmanagerV1alpha2().Certificates(ns.Name).List(ctx, metav1.ListOptions{
				LabelSelector: o.LabelSelector,
			})
			if err != nil {
				return err
			}

			crts = append(crts, crtsList.Items...)

		default:
			for _, crtName := range args {
				crt, err := o.CMClient.CertmanagerV1alpha2().Certificates(ns.Name).Get(ctx, crtName, metav1.GetOptions{})
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

	if o.Wait {
		if err := o.waitCertificatesReady(ctx, crts); err != nil {
			return err
		}

		fmt.Fprintf(o.Out, "%d Certificates successfully renewed\n", len(crts))
	}

	return nil
}

func (o *Options) renewCertificate(ctx context.Context, crt *cmapi.Certificate) error {
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "ManuallyTriggered", "Certificate re-issuance manually triggered")
	_, err := o.CMClient.CertmanagerV1alpha2().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to trigger issuance of Certificate %s/%s: %v", crt.Namespace, crt.Name, err)
	}
	fmt.Fprintf(o.Out, "Manually triggered issuance of Certificate %s/%s\n", crt.Namespace, crt.Name)
	return nil
}

func (o *Options) waitCertificatesReady(ctx context.Context, crts []cmapi.Certificate) error {
	ticker := time.NewTicker(pollTime)
	defer ticker.Stop()

	if o.Timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}

	for {
		lenReady := 0

		for _, crt := range crts {
			crt, err := o.CMClient.CertmanagerV1alpha2().Certificates(crt.Namespace).Get(ctx, crt.Name, metav1.GetOptions{})
			if err != nil {
				// TODO: handle certificate no longer existing?
				return err
			}

			// If still in Issuing=true state, continue
			if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond != nil && cond.Status == cmmeta.ConditionTrue {
				continue
			}

			// If Certificate is in a ready state, add ready
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
			return fmt.Errorf("within %s %d Certificates failed to become ready in time",
				o.Timeout, len(crts)-lenReady)
		}
	}
}
