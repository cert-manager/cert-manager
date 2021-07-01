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
	"github.com/spf13/pflag"

	"helm.sh/helm/v3/pkg/cli"
)

func CopyCliFlags(flags *pflag.FlagSet, defaults map[string]string, cliEnvSettings *cli.EnvSettings) error {
	// Pass namespace value through fake flags, because it is a private property
	fakefs := pflag.NewFlagSet("fake", pflag.ExitOnError)
	cliEnvSettings.AddFlags(fakefs)

	for name, value := range defaults {
		if err := fakefs.Set(name, value); err != nil {
			return err
		}
	}

	var err error = nil
	flags.VisitAll(func(flag *pflag.Flag) {
		if err != nil || !flag.Changed {
			return
		}
		err = fakefs.Set(flag.Name, flag.Value.String())
	})
	if err != nil {
		return err
	}

	if err := fakefs.Parse([]string{}); err != nil {
		return err
	}

	return nil
}
