/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package config

import (
	"flag"
	"fmt"
)

type Helm struct {
	// Path to the Helm binary to use during tests
	Path string
}

func (n *Helm) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&n.Path, "helm-binary-path", "helm", "path to the helm binary to use in tests")
}

func (n *Helm) Validate() []error {
	var errs []error
	if n.Path == "" {
		errs = append(errs, fmt.Errorf("--helm-binary-path must be specified"))
	}
	return errs
}
