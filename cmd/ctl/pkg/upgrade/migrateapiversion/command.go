/*
Copyright 2022 The cert-manager Authors.

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

package migrateapiversion

import (
	"context"

	"github.com/spf13/cobra"
	apiextinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	acmeinstall "github.com/cert-manager/cert-manager/internal/apis/acme/install"
	cminstall "github.com/cert-manager/cert-manager/internal/apis/certmanager/install"
)

var (
	long = templates.LongDesc(i18n.T(`
Ensures resources in your Kubernetes cluster are persisted in the v1 API version.

This must be run prior to upgrading to ensure your cluster is ready to upgrade to cert-manager v1.7 and beyond.

This command must be run with a cluster running cert-manager v1.0 or greater.`))

	example = templates.Examples(i18n.T(build.WithTemplate(`
# Check the cert-manager installation is ready to be upgraded to v1.7 and perform necessary migrations
# to ensure that the kube-apiserver has stored only v1 API versions.
{{.BuildName}} upgrade migrate-api-version

# Force migrations to be run, even if the 'status.storedVersion' field on the CRDs does not contain
# old, deprecated API versions.
# This should only be used if you have manually edited/patched the CRDs already.
# It will force a read and a write of ALL cert-manager resources unconditionally.
{{.BuildName}} upgrade migrate-api-version --skip-stored-version-check
`)))
)

// Options is a struct to support renew command
type Options struct {
	genericclioptions.IOStreams
	*factory.Factory

	client                 client.Client
	skipStoredVersionCheck bool
	qps                    float32
	burst                  int
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdMigrate returns a cobra command for updating resources in an apiserver
// to force a new storage version to be used.
func NewCmdMigrate(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "migrate-api-version",
		Short:   "Migrate all existing persisted cert-manager resources to the v1 API version",
		Long:    long,
		Example: example,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Complete())
			cmdutil.CheckErr(o.Run(ctx, args))
		},
	}

	cmd.Flags().BoolVar(&o.skipStoredVersionCheck, "skip-stored-version-check", o.skipStoredVersionCheck, ""+
		"If true, all resources will be read and written regardless of the 'status.storedVersions' on the CRD resource. "+
		"Use this mode if you have previously manually modified the 'status.storedVersions' field on CRD resources.")
	cmd.Flags().Float32Var(&o.qps, "qps", 5, "Indicates the maximum QPS to the apiserver from the client.")
	cmd.Flags().IntVar(&o.burst, "burst", 10, "Maximum burst value for queries set to the apiserver from the client.")
	o.Factory = factory.New(ctx, cmd)

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(_ []string) error {
	return nil
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete() error {
	var err error
	scheme := runtime.NewScheme()
	apiextinstall.Install(scheme)
	cminstall.Install(scheme)
	acmeinstall.Install(scheme)

	if o.qps != 0 {
		o.RESTConfig.QPS = o.qps
	}
	if o.burst != 0 {
		o.RESTConfig.Burst = o.burst
	}
	o.client, err = client.New(o.RESTConfig, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	return nil
}

// Run executes renew command
func (o *Options) Run(ctx context.Context, args []string) error {
	_, err := NewMigrator(o.client, o.skipStoredVersionCheck, o.Out, o.ErrOut).Run(ctx, "v1", []string{
		"certificates.cert-manager.io",
		"certificaterequests.cert-manager.io",
		"issuers.cert-manager.io",
		"clusterissuers.cert-manager.io",
		"orders.acme.cert-manager.io",
		"challenges.acme.cert-manager.io",
	})
	return err
}
