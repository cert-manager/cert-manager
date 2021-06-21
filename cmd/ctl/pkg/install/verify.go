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
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"

	helm "github.com/jetstack/cert-manager/cmd/ctl/pkg/install/helm"
	verify "github.com/jetstack/cert-manager/cmd/ctl/pkg/install/verify"
)

type VerifyOptions struct {
	settings  *cli.EnvSettings
	client    *action.Install
	cfg       *action.Configuration
	valueOpts *values.Options

	ChartName        string
	SkipInstallCheck bool
	VerifyTimeout    time.Duration

	genericclioptions.IOStreams
}

// TODO: add more docs
// Usage: "kubectl cert-manager verify"

func NewCmdVerify(ctx context.Context, ioStreams genericclioptions.IOStreams, f cmdutil.Factory) *cobra.Command {
	settings := cli.New()
	cfg := new(action.Configuration)
	if err := cfg.Init(settings.RESTClientGetter(), settings.Namespace(), os.Getenv("HELM_DRIVER"), log.Printf); err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	options := &VerifyOptions{
		settings:  settings,
		client:    action.NewInstall(cfg),
		cfg:       cfg,
		valueOpts: &values.Options{},
		IOStreams: ioStreams,
	}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Cert Manager verifier helps to verify your cert-manager installation",
		Long: `Cert Manager is used widely in kubernetes clusters and many things depend on it. 
			Unfortunately it's not so easy to know that cert-manager is installed and readiness probes are not
			enough here.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return options.runVerify(ctx)
		},
		SilenceUsage: true,
	}

	addInstallFlags(cmd.Flags(), options.client)
	addValueOptionsFlags(cmd.Flags(), options.valueOpts)
	addChartPathOptionsFlags(cmd.Flags(), &options.client.ChartPathOptions)

	cmd.Flags().StringVar(&options.ChartName, "chart-name", "cert-manager", "Name of the cert-manager chart")
	cmd.Flags().BoolVar(&options.SkipInstallCheck, "skip-install-check", false, "do not check for existing cert-manager crds")
	cmd.Flags().DurationVar(&options.VerifyTimeout, "verify-timeout", 120*time.Second, "Timeout after which we give up waiting for cert-manager to be ready.")

	return cmd
}

func (o *VerifyOptions) runVerify(ctx context.Context) error {
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
	chartValues["installCRDs"] = true
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
	if !o.SkipInstallCheck && len(installedCrds) != len(crds) {
		return fmt.Errorf(
			"Some of the cert-manager crds are not installed.",
		)
	}

	deployments, err := helm.FilterDeploymentResources(resouces)
	if err != nil {
		return err
	}

	config, err := o.cfg.RESTClientGetter.ToRESTConfig()
	if err != nil {
		return err
	}

	verifyCtx, cancel := context.WithTimeout(context.Background(), o.VerifyTimeout)
	defer cancel()

	result, err := verify.Verify(verifyCtx, config, &verify.Options{
		Namespace:   o.client.Namespace,
		Deployments: deployments,

		IOStreams: o.IOStreams,
	})
	if err != nil {
		return err
	}

	log.Printf(formatDeploymentResult(result.DeploymentsResult))

	if !result.DeploymentsSuccess {
		return fmt.Errorf("FAILED! Not all deployments are ready.")
	}

	if result.CertificateError != nil {
		log.Printf("error when waiting for certificate to be ready: %v", result.CertificateError)
		return err
	}
	log.Printf("ヽ(•‿•)ノ Cert-manager is READY!")

	return nil
}

func formatDeploymentResult(result []verify.DeploymentResult) string {
	var formattedResult string
	for _, r := range result {
		if r.Status == verify.Ready {
			formattedResult += fmt.Sprintf("Deployment %s READY! ヽ(•‿•)ノ\n", r.Deployment.Name)
		} else if r.Status == verify.NotReady {
			formattedResult += fmt.Sprintf("Deployment %s not ready. Reason: %s\n", r.Deployment.Name, r.Error.Error())
		} else {
			formattedResult += fmt.Sprintf("Deployment %s not found. Required?: %t\n", r.Deployment.Name, r.Deployment.Required)
		}
	}
	return formattedResult
}
