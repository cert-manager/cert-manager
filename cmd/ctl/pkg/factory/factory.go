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

package factory

import (
	"context"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/cmd/util"

	// Load all auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
)

var (
	kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	factory         = util.NewFactory(kubeConfigFlags)
)

// Factory provides a set of clients and configurations to authenticate and
// access a target Kubernetes cluster. Factory will ensure that its fields are
// populated and valid during command execution.
type Factory struct {
	// Namespace is the namespace that the user has requested with the
	// "--namespace" / "-n" flag. Defaults to "default" if the flag was not
	// provided.
	Namespace string

	// EnforceNamespace will be true if the user provided the namespace flag.
	EnforceNamespace bool

	// RESTConfig is a Kubernetes REST config that contains the user's
	// authentication and access configuration.
	RESTConfig *rest.Config

	// CMClient is a Kubernetes clientset for interacting with cert-manager APIs.
	CMClient cmclient.Interface

	// KubeClient is a Kubernetes clientset for interacting with the base
	// Kubernetes APIs.
	KubeClient kubernetes.Interface

	// RESTClientGetter is used to get RESTConfig, DiscoveryClients and
	// RESTMapper implementations
	RESTClientGetter genericclioptions.RESTClientGetter
}

// New returns a new Factory. The supplied command will have flags registered
// for interacting with the Kubernetes access options. Factory will be
// populated when the command is executed using the cobra PreRun. If a PreRun
// is already defined, it will be executed _after_ Factory has been populated,
// making it available.
func New(ctx context.Context, cmd *cobra.Command) *Factory {
	f := new(Factory)

	kubeConfigFlags.AddFlags(cmd.Flags())
	cmd.RegisterFlagCompletionFunc("namespace", validArgsListNamespaces(ctx, f))

	// Setup a PreRunE to populate the Factory. Catch the existing PreRunE command
	// if one was defined, and execute it second.
	existingPreRunE := cmd.PreRunE
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if err := f.complete(); err != nil {
			return err
		}

		if existingPreRunE != nil {
			return existingPreRunE(cmd, args)
		}
		return nil
	}

	return f
}

// complete will populate the Factory with values using the shared Kubernetes
// CLI factory.
func (f *Factory) complete() error {
	var err error

	f.Namespace, f.EnforceNamespace, err = factory.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	f.RESTConfig, err = factory.ToRESTConfig()
	if err != nil {
		return err
	}

	f.KubeClient, err = kubernetes.NewForConfig(f.RESTConfig)
	if err != nil {
		return err
	}

	f.CMClient, err = cmclient.NewForConfig(f.RESTConfig)
	if err != nil {
		return err
	}

	f.RESTClientGetter = factory

	return nil
}
