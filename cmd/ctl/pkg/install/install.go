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
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/release"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/install/helm"
)

type InstallOptions struct {
	settings  *cli.EnvSettings
	client    *action.Install
	cfg       *action.Configuration
	valueOpts *values.Options

	ChartName string
	DryRun    bool
	Wait      bool

	genericclioptions.IOStreams
}

const (
	installCRDsFlagName         = "installCRDs"
	defaultCertManagerNamespace = "cert-manager"
)

func installDesc() string {
	return build.WithTemplate(`This command installs cert-manager. It uses the Helm libraries to do so.

The latest published cert-manager chart in the "https://charts.jetstack.io" repo is used.
Most of the features supported by 'helm install' are also supported by this command.
In addition, this command will always correctly install the required CRD resources.

Some example uses:
	$ {{.BuildName}} x install
or
	$ {{.BuildName}} x install -n new-cert-manager
or
	$ {{.BuildName}} x install --version v1.4.0
or
	$ {{.BuildName}} x install --set prometheus.enabled=false

To override values in the cert-manager chart, use either the '--values' flag and
pass in a file or use the '--set' flag and pass configuration from the command line.
`)
}

func NewCmdInstall(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	settings := cli.New()
	cfg := new(action.Configuration)

	options := &InstallOptions{
		settings:  settings,
		cfg:       cfg,
		client:    action.NewInstall(cfg),
		valueOpts: &values.Options{},

		IOStreams: ioStreams,
	}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install cert-manager",
		Long:  installDesc(),
		RunE: func(cmd *cobra.Command, args []string) error {
			options.client.Namespace = settings.Namespace()

			rel, err := options.runInstall(ctx)
			if err != nil {
				return err
			}

			if options.DryRun {
				fmt.Fprintf(ioStreams.Out, "%s", rel.Manifest)
				return nil
			}

			printReleaseSummary(ioStreams.Out, rel)
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	settings.AddFlags(cmd.Flags())

	// The Helm cli.New function does not provide an easy way to
	// override the default of the namespace flag.
	// See https://github.com/helm/helm/issues/9790
	//
	// Here we set the default value shown in the usage message.
	cmd.Flag("namespace").DefValue = defaultCertManagerNamespace
	// Here we set the default value.
	// The returned error is ignored because
	// pflag.stringValue.Set always returns a nil.
	cmd.Flag("namespace").Value.Set(defaultCertManagerNamespace)

	addInstallUninstallFlags(cmd.Flags(), &options.client.Timeout, &options.Wait)

	addInstallFlags(cmd.Flags(), options.client)
	addValueOptionsFlags(cmd.Flags(), options.valueOpts)
	addChartPathOptionsFlags(cmd.Flags(), &options.client.ChartPathOptions)

	cmd.Flags().BoolVar(&options.client.CreateNamespace, "create-namespace", true, "Create the release namespace if not present")
	cmd.Flags().MarkHidden("create-namespace")
	cmd.Flags().StringVar(&options.ChartName, "chart-name", "cert-manager", "Name of the chart to install")
	cmd.Flags().MarkHidden("chart-name")
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "Simulate install and output manifest")

	return cmd
}

// The overall strategy is to install the CRDs first, and not as part of a Helm
// release, and then to install a Helm release without the CRDs.  This is to
// ensure that CRDs are not removed by a subsequent helm uninstall or by a
// future cmctl uninstall. We want the removal of CRDs to only be performed by
// an administrator who understands that the consequences of removing CRDs will
// be the garbage collection of all the related CRs in the cluster.  We first
// do a dry-run install of the chart (effectively helm template
// --validate=false) to render the CRDs from the CRD templates in the Chart.
// The ClientOnly option is required, otherwise Helm will return an error in
// case the CRDs are already installed in the cluster.  We then extract the
// CRDs from the resulting dry-run manifests and install those first.  Finally,
// we perform a helm install to install the remaining non-CRD resources and
// wait for those to be "Ready".
// This creates a Helm "release" artifact in a Secret in the target namespace, which contains
// a record of all the resources installed by Helm (except the CRDs).
func (o *InstallOptions) runInstall(ctx context.Context) (*release.Release, error) {
	log.SetFlags(0)         // Disable prefixing logs with timestamps.
	log.SetOutput(o.ErrOut) // Log everything to stderr so dry-run output does not get corrupted.

	// Find chart
	cp, err := o.client.ChartPathOptions.LocateChart(o.ChartName, o.settings)
	if err != nil {
		return nil, err
	}

	chart, err := loader.Load(cp)
	if err != nil {
		return nil, err
	}

	// Check if chart is installable
	if err := checkIfInstallable(chart); err != nil {
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

	// Dryrun template generation (used for rendering the CRDs in /templates)
	o.client.DryRun = true                  // Do not apply install
	o.client.ClientOnly = true              // Do not validate against cluster (otherwise double CRDs can cause error)
	chartValues[installCRDsFlagName] = true // Make sure to render CRDs
	dryRunResult, err := o.client.Run(chart, chartValues)
	if err != nil {
		return nil, err
	}

	if o.DryRun {
		return dryRunResult, nil
	}

	if err := o.cfg.Init(o.settings.RESTClientGetter(), o.settings.Namespace(), os.Getenv("HELM_DRIVER"), log.Printf); err != nil {
		return nil, err
	}

	// Extract the resource.Info objects from the manifest
	resources, err := helm.ParseMultiDocumentYAML(dryRunResult.Manifest, o.cfg.KubeClient)
	if err != nil {
		return nil, err
	}

	// Filter resource.Info objects and only keep the CRDs
	crds := helm.FilterCrdResources(resources)

	// Abort in case CRDs were not found in chart
	if len(crds) == 0 {
		return nil, fmt.Errorf("Found no CRDs in provided cert-manager chart.")
	}

	// Make sure that no CRDs are currently installed
	originalCRDs, err := helm.FetchResources(crds, o.cfg.KubeClient)
	if err != nil {
		return nil, err
	}

	if len(originalCRDs) > 0 {
		return nil, fmt.Errorf("Found existing installed cert-manager CRDs! Cannot continue with installation.")
	}

	// Install CRDs
	if err := helm.CreateCRDs(crds, o.cfg); err != nil {
		return nil, err
	}

	// Install chart
	o.client.DryRun = false     // Apply DryRun cli flags
	o.client.ClientOnly = false // Perform install against cluster

	o.client.Wait = o.Wait // Wait for resources to be ready
	// If part of the install fails and the Atomic option is set to True,
	// all resource installs are reverted. Atomic cannot be enabled without
	// waiting (if Atomic=True is set, the value for Wait is overwritten with True),
	// so only enable Atomic if we are waiting.
	o.client.Atomic = o.Wait
	// The cert-manager chart currently has only a startupapicheck hook,
	// if waiting is disabled, this hook should be disabled too; otherwise
	// the hook will still wait for the installation to succeed.
	o.client.DisableHooks = !o.Wait

	chartValues[installCRDsFlagName] = false // Do not render CRDs, as this might cause problems when uninstalling using helm

	return o.client.Run(chart, chartValues)
}

func printReleaseSummary(out io.Writer, rel *release.Release) {
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
}

// Only Application chart type are installable.
func checkIfInstallable(ch *chart.Chart) error {
	switch ch.Metadata.Type {
	case "", "application":
		return nil
	}
	return fmt.Errorf("%s charts are not installable", ch.Metadata.Type)
}
