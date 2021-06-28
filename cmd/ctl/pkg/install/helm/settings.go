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

package helm

import (
	flag "github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"helm.sh/helm/v3/pkg/cli"
)

func CopyCliFlags(kubeConfigFlags *genericclioptions.ConfigFlags, cliEnvSettings *cli.EnvSettings) error {
	// Pass namespace value through fake flags, because it is a private property
	fakefs := flag.NewFlagSet("fake", flag.ExitOnError)
	cliEnvSettings.AddFlags(fakefs)
	if err := fakefs.Set("namespace", *kubeConfigFlags.Namespace); err != nil {
		return err
	}
	if err := fakefs.Parse([]string{}); err != nil {
		return err
	}

	cliEnvSettings.KubeConfig = *kubeConfigFlags.KubeConfig
	cliEnvSettings.KubeContext = *kubeConfigFlags.Context
	cliEnvSettings.KubeToken = *kubeConfigFlags.BearerToken
	cliEnvSettings.KubeAsUser = *kubeConfigFlags.Impersonate
	cliEnvSettings.KubeAsGroups = *kubeConfigFlags.ImpersonateGroup
	cliEnvSettings.KubeAPIServer = *kubeConfigFlags.APIServer
	cliEnvSettings.KubeCaFile = *kubeConfigFlags.CAFile

	return nil
}
