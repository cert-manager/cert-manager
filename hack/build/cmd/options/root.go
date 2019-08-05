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

package options

import (
	"os"

	"github.com/spf13/pflag"
)

type Root struct {
	// Absolute path to the root of the cert-manager repository
	RepoRoot string

	// If true, live command output and additional debugging info will be printed
	Debug bool
}

func (o *Root) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.RepoRoot, "repo-root", defaultRepoRoot(), "path to the root of the cert-manager repository")
	fs.BoolVar(&o.Debug, "debug", false, "if true, live command output and additional debugging info will be printed")
}

func defaultRepoRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		panic("error getting working directory: " + err.Error())
	}
	return wd
}
