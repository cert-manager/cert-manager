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

package uninstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/storage/driver"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/install/helm"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type options struct {
	settings *helm.NormalisedEnvSettings
	client   *action.Uninstall
	cfg      *action.Configuration
	logFn    func(format string, v ...interface{})

	releaseName  string
	disableHooks bool
	dryRun       bool
	wait         bool

	genericclioptions.IOStreams
}

const (
	releaseName = "cert-manager"
)

func description() string {
	return build.WithTemplate(`This command uninstalls any Helm-managed release of cert-manager.

The CRDs will be deleted if you installed cert-manager with the option --set CRDs=true.

Most of the features supported by 'helm uninstall' are also supported by this command.

Some example uses:
	$ {{.BuildName}} x uninstall
or
	$ {{.BuildName}} x uninstall --namespace my-cert-manager
or
	$ {{.BuildName}} x uninstall --dry-run
or
	$ {{.BuildName}} x uninstall --no-hooks
`)
}

func NewCmd(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	log := logf.FromContext(ctx, "install")
	logFn := func(format string, v ...interface{}) {
		log.Info(fmt.Sprintf(format, v...))
	}

	settings := helm.NewNormalisedEnvSettings()
	cfg := &action.Configuration{Log: logFn}

	options := options{
		settings: settings,
		cfg:      cfg,
		client:   action.NewUninstall(cfg),
		logFn:    logFn,

		IOStreams: ioStreams,
	}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall cert-manager",
		Long:  description(),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := run(ctx, options)
			if err != nil {
				return err
			}

			if options.dryRun {
				fmt.Fprintf(ioStreams.Out, "%s", res.Release.Manifest)
				return nil
			}

			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	settings.Setup(ctx, cmd)

	cmd.Flags().DurationVar(&options.client.Timeout, "timeout", 5*time.Minute, "time to wait for any individual Kubernetes operation (like Jobs for hooks)")
	cmd.Flags().StringVar(&options.releaseName, "release-name", releaseName, "name of the helm release to uninstall")
	cmd.Flags().BoolVar(&options.wait, "wait", true, "if set, will wait until all the resources are deleted before returning. It will wait for as long as --timeout")
	cmd.Flags().BoolVar(&options.dryRun, "dry-run", false, "simulate uninstall and output manifests to be deleted")
	cmd.Flags().BoolVar(&options.disableHooks, "no-hooks", false, "prevent hooks from running during uninstallation (pre- and post-uninstall hooks)")

	return cmd
}

// run assumes cert-manager was installed as a Helm release named cert-manager.
// this is not configurable to avoid uninstalling non-cert-manager releases.
func run(ctx context.Context, o options) (*release.UninstallReleaseResponse, error) {
	if err := o.cfg.Init(o.settings.Factory.RESTClientGetter, o.settings.Namespace(), os.Getenv("HELM_DRIVER"), o.logFn); err != nil {
		return nil, fmt.Errorf("o.cfg.Init: %v", err)
	}

	o.client.DisableHooks = o.disableHooks
	o.client.DryRun = o.dryRun
	o.client.Wait = o.wait

	res, err := o.client.Run(o.releaseName)

	if errors.Is(err, driver.ErrReleaseNotFound) {
		return nil, fmt.Errorf("release %v not found in namespace %v, did you use the correct namespace?", releaseName, o.settings.Namespace())
	}

	return res, nil
}
