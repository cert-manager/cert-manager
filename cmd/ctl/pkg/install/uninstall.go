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

package install

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/release"

	helm "github.com/jetstack/cert-manager/cmd/ctl/pkg/install/helm"
)

const uninstallDesc = `
This command uninstalls cert-manager.

It uses the latest published cert-manager chart on the "https://charts.jetstack.io" repo.
Most of the features supported by 'helm install' and 'helm uninstall' are also supported
by this command. Additional the the functionallity that the helm command gives you, this
command can also delete CRD resources using the '--remove-crds' flag. The command first
uninstalls the cert-manager helm deployments and also uninstalls the resources generated
by the helm template. The tool can thus be used to uninstall cert-manager even if it was
installed using the static manifests or another method.

Some example uses:
	$ kubectl cert-manager uninstall
or
	$ kubectl cert-manager uninstall --remove-crds
or
	$ kubectl cert-manager uninstall --namespace cert-manager-namespace
`

type UninstallOptions struct {
	settings        *cli.EnvSettings
	installClient   *action.Install
	uninstallClient *action.Uninstall
	cfg             *action.Configuration
	valueOpts       *values.Options

	ChartName  string
	RemoveCrds bool

	genericclioptions.IOStreams
}

// TODO: should wait for uninstall (https://github.com/helm/helm/pull/9702)
func NewCmdUninstall(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	settings := cli.New()
	cfg := new(action.Configuration)
	if err := cfg.Init(settings.RESTClientGetter(), settings.Namespace(), os.Getenv("HELM_DRIVER"), log.Printf); err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	options := &UninstallOptions{
		settings:        settings,
		installClient:   action.NewInstall(cfg),
		uninstallClient: action.NewUninstall(cfg),
		cfg:             cfg,
		valueOpts:       &values.Options{},
		IOStreams:       ioStreams,
	}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "uninstall cert-manager",
		Long:  uninstallDesc,
		RunE: func(_ *cobra.Command, args []string) error {
			return options.runUninstall(ctx)
		},
		SilenceUsage: true,
	}

	addInstallFlags(cmd.Flags(), options.installClient)
	addValueOptionsFlags(cmd.Flags(), options.valueOpts)
	addChartPathOptionsFlags(cmd.Flags(), &options.installClient.ChartPathOptions)

	cmd.Flags().StringVar(&options.ChartName, "chart-name", "cert-manager", "name of the cert-manager chart")
	cmd.Flags().BoolVar(&options.RemoveCrds, "remove-crds", false, "also remove cert-manager crds")

	return cmd
}

func (o *UninstallOptions) runUninstall(ctx context.Context) error {
	log.SetFlags(0)
	log.SetOutput(o.Out)

	// 1. find chart
	cp, err := o.installClient.ChartPathOptions.LocateChart(o.ChartName, o.settings)
	if err != nil {
		return err
	}

	chart, err := helm.LoadChart(cp, o.installClient, o.settings)
	if err != nil {
		return err
	}

	// Check if chart is installable
	if err := helm.CheckIfInstallable(chart); err != nil {
		return err
	}

	// Console print if chart is deprecated
	if chart.Metadata.Deprecated {
		log.Printf("This chart is deprecated")
	}

	// Merge all values flags
	p := getter.All(o.settings)
	chartValues, err := o.valueOpts.MergeValues(p)
	if err != nil {
		return err
	}

	// 2. do dryrun template generation (used for rendering the resources that should be deleted)
	o.installClient.DryRun = true
	o.installClient.IsUpgrade = true
	chartValues["installCRDs"] = o.RemoveCrds
	dryRunResult, err := o.installClient.Run(chart, chartValues)
	if err != nil {
		return err
	}

	// 3. Find helm releases created by a chart equal to ChartName and uninstall them
	certManagerReleases, err := o.cfg.Releases.List(func(rel *release.Release) bool {
		return rel.Chart.Name() == o.ChartName
	})

	for _, release := range certManagerReleases {
		o.uninstallClient.Run(release.Name)
	}

	// 4. Delete all resources that are present in the chart
	resources, err := helm.GetChartResourceInfo(chart, dryRunResult.Manifest, o.RemoveCrds, o.cfg.KubeClient)
	if err != nil {
		return err
	}

	if _, err := o.cfg.KubeClient.Delete(resources); err != nil {
		log.Printf("failed to delete %s", err)
		return errors.New(fmt.Sprintf("failed to delete %s", err))
	}

	return nil
}
