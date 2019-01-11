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

type Tiller struct {
	// Tiller image repo to use when deploying
	ImageRepo string

	// Tiller image tag to use when deploying
	ImageTag string
}

func (n *Tiller) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&n.ImageRepo, "tiller-image-repo", "gcr.io/kubernetes-helm/tiller", "docker image repo for tiller-deploy")
	fs.StringVar(&n.ImageTag, "tiller-image-tag", "bazel", "docker image tag for tiller-deploy")
}

func (n *Tiller) Validate() []error {
	var errs []error
	if n.ImageRepo == "" {
		errs = append(errs, fmt.Errorf("--tiller-image-repo must be specified"))
	}
	if n.ImageTag == "" {
		errs = append(errs, fmt.Errorf("--tiller-image-tag must be specified"))
	}
	return errs
}
