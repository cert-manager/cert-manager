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
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/release"

	helm "github.com/jetstack/cert-manager/cmd/ctl/pkg/install/helm"
)

const uninstallDesc = `
This command uninstalls cert-manager.

It can uninstall cert-manager even if it was installed by another install tool.

This command will also delete CRD resources when providing the '--remove-crds' flag.
It is safer to use this cli than using Helm directly (which might automatically remove
cert-manager crds when uninstalling, depending on the install parameters).

The tool tries to find a Helm-based cert-manager install (installed directly by Helm or
by this cli tool) and removes the resources based on the found Helm release.

Some example uses:
	$ kubectl cert-manager x uninstall
or
	$ kubectl cert-manager x uninstall --remove-crds
or
	$ kubectl cert-manager x uninstall -n new-cert-manager
`

type UninstallOptions struct {
	settings  *cli.EnvSettings
	cfg       *action.Configuration
	client    *action.Install
	valueOpts *values.Options

	ChartName  string
	RemoveCrds bool

	genericclioptions.IOStreams
}

func NewCmdUninstall(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	settings := cli.New()
	cfg := new(action.Configuration)

	options := &UninstallOptions{
		settings:  settings,
		cfg:       cfg,
		client:    action.NewInstall(cfg),
		valueOpts: &values.Options{},

		IOStreams: ioStreams,
	}

	// Set default namespace cli flag value
	defaults := make(map[string]string)
	defaults["namespace"] = "cert-manager"

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall cert-manager",
		Long:  uninstallDesc,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := helm.CopyCliFlags(cmd.Root().PersistentFlags(), defaults, settings); err != nil {
				return nil
			}
			options.client.Namespace = settings.Namespace()

			return options.runUninstall()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	addInstallUninstallFlags(cmd.Flags(), &options.client.Timeout, &options.client.Wait)

	cmd.Flags().BoolVar(&options.RemoveCrds, "remove-crds", false, "Also remove crds")
	cmd.Flags().StringVar(&options.ChartName, "chart-name", "Cert-manager", "name of the chart to uninstall")

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

	if len(certManagerReleases) == 0 {
		return fmt.Errorf("No helm-based (installed via helm or the cert-manager kubectl plugin) installation was found.")
	}

	log.Printf(">> Found a helm-based installation, will use the original chart for removal.")
	releaseName, ch, chartValues, err := o.chartAndOptionsFromRelease(certManagerReleases[0])
	if err != nil {
		return err
	}
	o.client.ReleaseName = releaseName

	// Dryrun template generation (used for rendering the resources that should be deleted)
	o.client.DryRun = true                          // Do not apply install
	o.client.IsUpgrade = true                       // Do not validate against cluster
	chartValues[installCRDsFlagName] = o.RemoveCrds // Only render crds if cli flag is provided
	dryRunResult, err := o.client.Run(ch, chartValues)
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

		if o.client.Wait {
			if err := o.waitForDeletedResources(resources); err != nil {
				return err
			}
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
		log.Printf(">> Everything was removed, also removing Helm entry.")
		return o.removeHelmReleaseAndHistory(certManagerReleases[0])
	}

	return nil
}

func (o *UninstallOptions) chartAndOptionsFromRelease(rel *release.Release) (string, *chart.Chart, map[string]interface{}, error) {
	if rel.Config == nil {
		rel.Config = make(map[string]interface{})
	}
	// Overwrite the installCRDs flag so that crds are ONLY removed if the command flag is set
	rel.Config[installCRDsFlagName] = o.RemoveCrds

	return rel.Name, rel.Chart, rel.Config, nil
}

// For sake of simplicity, don't allow to keep history. Equivalent with not allowing
// --keep-hisory flag to be true (https://helm.sh/docs/helm/helm_uninstall/).
func (o *UninstallOptions) removeHelmReleaseAndHistory(rel *release.Release) error {
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

// TODO: wait for uninstall should get merged into Helm (https://github.com/helm/helm/pull/9702)
// waitForDeletedResources polls to check if all the resources are deleted or a timeout is reached
func (o *UninstallOptions) waitForDeletedResources(deleted []*resource.Info) error {
	log.Printf("beginning wait for %d resources to be deleted with timeout of %v", len(deleted), o.client.Timeout)

	ctx, cancel := context.WithTimeout(context.Background(), o.client.Timeout)
	defer cancel()

	return wait.PollImmediateUntil(2*time.Second, func() (bool, error) {
		for _, v := range deleted {
			err := v.Get()
			if err == nil || !apierrors.IsNotFound(err) {
				return false, err
			}
		}
		return true, nil
	}, ctx.Done())
}
