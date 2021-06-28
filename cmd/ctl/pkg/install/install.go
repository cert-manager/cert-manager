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
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/release"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/install/helm"
)

type InstallOptions struct {
	settings  *cli.EnvSettings
	client    *action.Install
	cfg       *action.Configuration
	valueOpts *values.Options

	ChartName string
	DryRun    bool

	genericclioptions.IOStreams
}

const installCRDsFlagName = "installCRDs"
const installDesc = `
This command installs cert-manager. It uses the helm libraries to do so.

The latest published cert-manager chart on the "https://charts.jetstack.io" repo is used.
Most of the features supported by 'helm install' are also supported by this command.
Additional the the functionallity that the helm command gives you, this command will
also manage CRD resources.

Some example uses:
	$ kubectl cert-manager install -n cert-manager
or
	$ kubectl cert-manager install -n cert-manager --version v1.4.0
or
	$ kubectl cert-manager install -n cert-manager --set prometheus.enabled=false

To override values in the cert-manager chart, use either the '--values' flag and pass in a file
or use the '--set' flag and pass configuration from the command line, to force
a string value use '--set-string'. In case a value is large and therefore
you want not to use neither '--values' nor '--set', use '--set-file' to read the
single large value from file.
`

func NewCmdInstall(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory, kubeConfigFlags *genericclioptions.ConfigFlags) *cobra.Command {
	settings := cli.New()
	cfg := new(action.Configuration)

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
			if err := helm.CopyCliFlags(kubeConfigFlags, settings); err != nil {
				return nil
			}
			options.client.Namespace = settings.Namespace()

			rel, err := options.runInstall(ctx)
			if err != nil {
				return err
			}
			return writeRelease(ioStreams.Out, rel, false)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	addInstallUninstallFlags(cmd.Flags(), options.client)
	addValueOptionsFlags(cmd.Flags(), options.valueOpts)
	addChartPathOptionsFlags(cmd.Flags(), &options.client.ChartPathOptions)

	cmd.Flags().BoolVar(&options.client.CreateNamespace, "create-namespace", true, "create the release namespace if not present")
	cmd.Flags().StringVar(&options.ChartName, "chart-name", "cert-manager", "name of the cert-manager chart")
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "simulate an install")

	return cmd
}

func (o *InstallOptions) runInstall(ctx context.Context) (*release.Release, error) {
	log.SetFlags(0)
	log.SetOutput(o.Out)

	if err := o.cfg.Init(o.settings.RESTClientGetter(), o.settings.Namespace(), os.Getenv("HELM_DRIVER"), log.Printf); err != nil {
		return nil, err
	}

	// Find chart
	cp, err := o.client.ChartPathOptions.LocateChart(o.ChartName, o.settings)
	if err != nil {
		return nil, err
	}

	chart, err := helm.LoadChart(cp, o.client, o.settings)
	if err != nil {
		return nil, err
	}

	// Check if chart is installable
	if err := helm.CheckIfInstallable(chart); err != nil {
		return nil, err
	}

	// Console print if chart is deprecated
	if chart.Metadata.Deprecated {
		log.Printf("This chart is deprecated")
	}

	// Merge all values flags
	p := getter.All(o.settings)
	chartValues, err := o.valueOpts.MergeValues(p)
	if err != nil {
		return nil, err
	}

	// Dryrun template generation (used for rendering the crds in /templates)
	o.client.DryRun = true                  // Do not apply install
	o.client.IsUpgrade = true               // Do not validate against cluster
	chartValues[installCRDsFlagName] = true // Make sure to render crds
	dryRunResult, err := o.client.Run(chart, chartValues)
	if err != nil {
		return nil, err
	}

	// Extract the resource.Info objects from the helm chart crds (/crds folder) and the manifest
	resources, err := helm.GetChartResourceInfo(chart, dryRunResult.Manifest, true, o.cfg.KubeClient)
	if err != nil {
		return nil, err
	}

	// Filter resource.Info objects and only keep the crds
	crds := helm.FilterCrdResources(resources)

	// Check if any of these CRDs do already exist
	installedCrds, err := helm.FetchResources(crds, o.cfg.KubeClient)
	if err != nil {
		return nil, err
	}

	// Abort in case crds are already installed
	if len(installedCrds) > 0 {
		return nil, fmt.Errorf("Found existing installed cert-manager crds! Cannot continue with installation.")
	}

	// Install CRDs
	if len(crds) > 0 && !o.DryRun {
		if err := helm.ApplyCRDs(helm.Create, crds, o.cfg); err != nil {
			return nil, err
		}
	}

	// Install chart
	o.client.DryRun = o.DryRun               // Apply DryRun cli flags
	o.client.IsUpgrade = false               // Reset value to false
	o.client.Atomic = true                   // If part of the install fails, also undo other installed resources
	chartValues[installCRDsFlagName] = false // Do not render crds, as this might cause problems when uninstalling using helm

	return o.client.Run(chart, chartValues)
}

func writeRelease(out io.Writer, rel *release.Release, debug bool) error {
	fmt.Fprintf(out, "NAME: %s\n", rel.Name)
	if !rel.Info.LastDeployed.IsZero() {
		fmt.Fprintf(out, "LAST DEPLOYED: %s\n", rel.Info.LastDeployed.Format(time.ANSIC))
	}
	fmt.Fprintf(out, "NAMESPACE: %s\n", rel.Namespace)
	fmt.Fprintf(out, "STATUS: %s\n", rel.Info.Status.String())
	fmt.Fprintf(out, "REVISION: %d\n", rel.Version)
	fmt.Fprintf(out, "DESCRIPTION: %s\n", rel.Info.Description)

	if len(rel.Info.Notes) > 0 {
		fmt.Fprintf(out, "NOTES:\n%s\n", strings.TrimSpace(rel.Info.Notes))
	}
	return nil
}
