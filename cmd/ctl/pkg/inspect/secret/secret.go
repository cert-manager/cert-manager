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

package secret

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	long = templates.LongDesc(i18n.T(`
Get details about a kubernetes.io/tls typed secret`))

	example = templates.Examples(i18n.T(`
# Query information about a secret with name 'my-crt' in namespace 'my-namespace'
kubectl cert-manager inspect secret my-crt --namespace my-namespace
`))
)

// Options is a struct to support status certificate command
type Options struct {
	RESTConfig *restclient.Config
	// The Namespace that the Certificate to be queried about resides in.
	// This flag registration is handled by cmdutil.Factory
	Namespace string

	clientSet *kubernetes.Clientset

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdInspectSecret returns a cobra command for status certificate
func NewCmdInspectSecret(ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "secret",
		Short:   "Get details about a kubernetes.io/tls typed secret",
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
		return errors.New("the name of the Secret has to be provided as argument")
	}
	if len(args) > 1 {
		return errors.New("only one argument can be passed in: the name of the Secret")
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

	o.clientSet, err = kubernetes.NewForConfig(o.RESTConfig)
	if err != nil {
		return err
	}

	return nil
}

// Run executes status certificate command
func (o *Options) Run(args []string) error {
	ctx := context.TODO()

	secret, err := o.clientSet.CoreV1().Secrets(o.Namespace).Get(ctx, args[0], metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error when finding Secret %q: %w\n", args[0], err)
	}

	// TODO: use cmmeta
	output, err := DescribeCertificate(secret.Data[corev1.TLSCertKey], secret.Data["ca.crt"])
	if err != nil {
		return fmt.Errorf("error when describing Secret %q: %w\n", args[0], err)
	}
	fmt.Println(output)

	return nil
}
