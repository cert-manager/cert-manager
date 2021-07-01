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
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/release"

	helm "github.com/jetstack/cert-manager/cmd/ctl/pkg/install/helm"
)

const uninstallDesc = `
This command uninstalls cert-manager.

It can uninstall cert-manager even if it was installed by another install tool.

This command will also delete CRD resources when providing the '--remove-crds' flag.
It is safer to use this cli than using helm directly (which might automatically remove
cert-manager crds when uninstalling, depending on the install parameters).

The tool first tries to find a helm-based cert-manager install (installed directly by helm
or by this cli tool) and removes the resources based on the found helm release. In case no
helm-based cert-manager install is found, a kubernetes manifest yamls are generated from
the provided chart and chart parameters and are used to determine what resources to remove
from the kubernetes cluster.

Some example uses:
	$ kubectl cert-manager uninstall
or
	$ kubectl cert-manager uninstall --remove-crds
or
	$ kubectl cert-manager uninstall -n new-cert-manager
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

	options := &UninstallOptions{
		settings:        settings,
		installClient:   action.NewInstall(cfg),
		uninstallClient: action.NewUninstall(cfg),
		cfg:             cfg,
		valueOpts:       &values.Options{},
		IOStreams:       ioStreams,
	}

	// Set default namespace cli flag value
	defaults := make(map[string]string)
	defaults["namespace"] = "cert-manager"

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "uninstall cert-manager",
		Long:  uninstallDesc,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := helm.CopyCliFlags(cmd.Root().PersistentFlags(), defaults, settings); err != nil {
				return nil
			}
			options.installClient.Namespace = settings.Namespace()

			return options.runUninstall()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	addInstallUninstallFlags(cmd.Flags(), options.installClient)
	addValueOptionsFlags(cmd.Flags(), options.valueOpts)
	addChartPathOptionsFlags(cmd.Flags(), &options.installClient.ChartPathOptions)

	cmd.Flags().StringVar(&options.ChartName, "chart-name", "cert-manager", "name of the cert-manager chart")
	cmd.Flags().BoolVar(&options.RemoveCrds, "remove-crds", false, "also remove cert-manager crds")

	return cmd
}

func (o *UninstallOptions) runUninstall() error {
	log.SetFlags(0)
	log.SetOutput(o.Out)

	if err := o.cfg.Init(o.settings.RESTClientGetter(), o.settings.Namespace(), os.Getenv("HELM_DRIVER"), log.Printf); err != nil {
		return err
	}

	// Find helm releases linked to a chart with the cert-manager ChartName
	certManagerReleases, err := o.cfg.Releases.List(func(rel *release.Release) bool {
		return rel.Chart.Name() == o.ChartName
	})
	if err != nil {
		return err
	}

	if len(certManagerReleases) > 1 {
		log.Printf(">> Found more than 1 cert-manager installation. Only one one of these installations will get uninstalled. Please rerun to also uninstall the other installations.")
	}

	var ch *chart.Chart
	var chartValues map[string]interface{}
	if len(certManagerReleases) > 0 {
		log.Printf(">> Found a helm-based installation, will use the original chart for removal.")
		ch, chartValues, err = o.chartAndOptionsFromRelease(certManagerReleases[0])
	} else {
		ch, chartValues, err = o.chartAndOptionsFromCliOptions()
	}
	if err != nil {
		return err
	}

	// Dryrun template generation (used for rendering the resources that should be deleted)
	o.installClient.DryRun = true                   // Do not apply install
	o.installClient.IsUpgrade = true                // Do not validate against cluster
	chartValues[installCRDsFlagName] = o.RemoveCrds // Only render crds if cli flag is provided
	dryRunResult, err := o.installClient.Run(ch, chartValues)
	if err != nil {
		return err
	}

	// Extract all resources that are present in the chart
	resources, err := helm.GetChartResourceInfo(dryRunResult.Manifest, o.cfg.KubeClient)
	if err != nil {
		return err
	}

	installedResources, err := helm.FetchResources(resources, o.cfg.KubeClient)
	if err != nil {
		return err
	}

	namespacedResources := helm.FilterNamespacedResources(installedResources, o.settings.Namespace())
	crdResources := helm.FilterCrdResources(installedResources)

	// Only delete in case we have found resources in the current namespace OR the only resources found are crds.
	if len(namespacedResources) > 0 || (len(installedResources) > 0 && len(installedResources) == len(crdResources)) {
		// Remove the resources that were generated, by calling the KubeClient directly
		if _, err := o.cfg.KubeClient.Delete(resources); err != nil {
			return fmt.Errorf("failed to delete %s", err)
		}
	} else if len(installedResources) > 0 {
		// Resources linked to cert-manager were found, but none were found in the current namespace.
		return fmt.Errorf("Only found non-namespaced resources linked to cert-manager. Make sure \"--namespace\" flag is set correctly.")
	} else if !o.RemoveCrds {
		// No resources were found that were generated by a cert-manager installation.
		// But we did not check for crds, so maybe we want to rerun with the --remove-crds flag set?
		log.Printf("Found nothing to uninstall. If you want to remove crds, rerun with the \"--remove-crds\" flag set.")
	} else {
		// No resources were found that were generated by a cert-manager installation.
		log.Printf("Found nothing to uninstall.")
	}

	if len(certManagerReleases) > 0 {
		log.Printf(">> Everything was removed, also removing helm entry.")
		return o.removeReleaseAndHistory(certManagerReleases[0])
	}

	return nil
}

func (o *UninstallOptions) chartAndOptionsFromRelease(rel *release.Release) (*chart.Chart, map[string]interface{}, error) {
	// Overwrite the installCRDs flag so that crds are ONLY removed if the command flag is set
	rel.Config[installCRDsFlagName] = o.RemoveCrds

	return rel.Chart, rel.Config, nil
}

// For sake of simplicity, don't allow to keep history. Equivalent with not allowing
// --keep-hisory flag to be true (https://helm.sh/docs/helm/helm_uninstall/).
func (o *UninstallOptions) removeReleaseAndHistory(rel *release.Release) error {
	rels, err := o.cfg.Releases.History(rel.Name)
	if err != nil {
		return err
	}

	for _, rel := range rels {
		if _, err := o.cfg.Releases.Delete(rel.Name, rel.Version); err != nil {
			return err
		}
	}
	return nil
}

func (o *UninstallOptions) chartAndOptionsFromCliOptions() (*chart.Chart, map[string]interface{}, error) {
	// Find chart
	cp, err := o.installClient.ChartPathOptions.LocateChart(o.ChartName, o.settings)
	if err != nil {
		return nil, nil, err
	}

	chart, err := helm.LoadChart(cp, o.installClient, o.settings)
	if err != nil {
		return nil, nil, err
	}

	// Check if chart is installable
	if err := helm.CheckIfInstallable(chart); err != nil {
		return nil, nil, err
	}

	// Console print if chart is deprecated
	if chart.Metadata.Deprecated {
		log.Printf("This chart is deprecated")
	}

	// Merge all values flags
	p := getter.All(o.settings)
	chartValues, err := o.valueOpts.MergeValues(p)
	if err != nil {
		return nil, nil, err
	}

	return chart, chartValues, nil
}
