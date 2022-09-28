/*
Copyright 2020 The cert-manager Authors.

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
)

type Ginkgo struct {
	ReportDirectory string
}

func (g *Ginkgo) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&g.ReportDirectory, "report-dir", "", "Optional directory to store junit output in. If not specified, no junit file will be output")
}

func (c *Ginkgo) Validate() []error {
	return nil
}
