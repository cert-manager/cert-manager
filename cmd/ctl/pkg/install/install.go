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

	helm "github.com/jetstack/cert-manager/cmd/ctl/pkg/install/helm"
)

type InstallOptions struct {
	settings  *cli.EnvSettings
	client    *action.Install
	cfg       *action.Configuration
	valueOpts *values.Options

	ChartName string

	genericclioptions.IOStreams
}

const installCRDsFlagName = "installCRDs"
const installDesc = `
This command installs cert-manager.

It uses the latest published cert-manager chart on the "https://charts.jetstack.io" repo.
Most of the features supported by 'helm install' are also supported by this command.
Additional the the functionallity that the helm command gives you, this command will
also manage CRD resources.

Some example uses:
	$ kubectl cert-manager install
or
	$ kubectl cert-manager install --version v1.4.0
or
	$ kubectl cert-manager install --set prometheus.enabled=false
or
	$ kubectl cert-manager install --namespace cert-manager-namespace

To override values in the cert-manager chart, use either the '--values' flag and pass in a file
or use the '--set' flag and pass configuration from the command line, to force
a string value use '--set-string'. In case a value is large and therefore
you want not to use neither '--values' nor '--set', use '--set-file' to read the
single large value from file.
`

func NewCmdInstall(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	settings := cli.New()
	cfg := new(action.Configuration)
	if err := cfg.Init(settings.RESTClientGetter(), settings.Namespace(), os.Getenv("HELM_DRIVER"), log.Printf); err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	options := &InstallOptions{
		settings:  settings,
		client:    action.NewInstall(cfg),
		cfg:       cfg,
		valueOpts: &values.Options{},
		IOStreams: ioStreams,
	}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "install cert-manager",
		Long:  installDesc,
		RunE: func(_ *cobra.Command, args []string) error {
			return options.runInstall(ctx)
		},
		SilenceUsage: true,
	}

	addInstallFlags(cmd.Flags(), options.client)
	addValueOptionsFlags(cmd.Flags(), options.valueOpts)
	addChartPathOptionsFlags(cmd.Flags(), &options.client.ChartPathOptions)

	cmd.Flags().StringVar(&options.ChartName, "chart-name", "cert-manager", "name of the cert-manager chart")

	return cmd
}

func (o *InstallOptions) runInstall(ctx context.Context) error {
	log.SetFlags(0)
	log.SetOutput(o.Out)

	// 1. find chart
	cp, err := o.client.ChartPathOptions.LocateChart(o.ChartName, o.settings)
	if err != nil {
		return err
	}

	chart, err := helm.LoadChart(cp, o.client, o.settings)
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

	// 2. do dryrun template generation (used for rendering the crds in /templates)
	o.client.DryRun = true
	o.client.IsUpgrade = true
	chartValues[installCRDsFlagName] = true
	dryRunResult, err := o.client.Run(chart, chartValues)
	if err != nil {
		return err
	}
	resouces, err := helm.GetChartResourceInfo(chart, dryRunResult.Manifest, true, o.cfg.KubeClient)
	if err != nil {
		return err
	}

	// 3. Collect all crds related to the chart
	crds, err := helm.FilterCrdResources(resouces)
	if err != nil {
		return err
	}

	// 4. Check if any of these CRDs do already exist
	installedCrds, err := helm.FetchResources(crds, o.cfg.KubeClient)
	if err != nil {
		return err
	}

	// User has to explicitly confirm in case crds are already installed
	if len(installedCrds) > 0 {
		return fmt.Errorf("Found existing installed cert-manager crds! Cannot continue with installation.")
	}

	// 5. install CRDs
	if len(crds) > 0 {
		if err := helm.ApplyCRDs(helm.Create, crds, o.cfg); err != nil {
			return err
		}
	}

	// 6. install chart
	o.client.DryRun = false
	o.client.IsUpgrade = false
	chartValues[installCRDsFlagName] = false
	_, err = o.client.Run(chart, chartValues)
	if err != nil {
		return err
	}

	return nil
}
