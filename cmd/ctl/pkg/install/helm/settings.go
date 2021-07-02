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

// The kubectl cert-manager plugin has a set of Global Flags that
// are used to create a cmdutil.Factory object. Unfortunately, this
// Factory is not usable by helm. Instead, we have to pass a
// cli.EnvSettings object. This EnvSettings object has private fields
// and can only be populated by setting the correct flags. Luckally,
// the flag names are identical, so we can copy all the flags from
// the kubectl flagset to a fake flagset that is linked to the helm
// EnvSettings. Furthermore, default values can be provided to this
// function. These defaults are used to initiate the EnvSettings values
// and are later overwritten by the kubectl flags that are set.
func CopyCliFlags(flags *pflag.FlagSet, defaults map[string]string, cliEnvSettings *cli.EnvSettings) error {
	// Create new fake flagset and link the flagset to Helm's EnvSettings
	fakefs := pflag.NewFlagSet("fake", pflag.ExitOnError)
	cliEnvSettings.AddFlags(fakefs)

	// Update the EnvSettings values to the provided default values
	for name, value := range defaults {
		if err := fakefs.Set(name, value); err != nil {
			return err
		}
	}

	// For each flag that was set in the kubectl flagset, overwrite the
	// flag value in the fake flagset.
	var err error = nil
	flags.VisitAll(func(flag *pflag.Flag) {
		// Skip in case flag was not changed
		if err != nil || !flag.Changed {
			return
		}
		err = fakefs.Set(flag.Name, flag.Value.String())
	})
	if err != nil {
		return err
	}

	return nil
}
