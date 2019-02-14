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

import "flag"

// Pebble global configuration for new Pebble instances
type Pebble struct {
	// Not currently exposed in Pebble addon
	// // ImageRepo for Pebble
	// ImageRepo string

	// // ImageTag for Pebble
	// ImageTag string
}

func (p *Pebble) AddFlags(fs *flag.FlagSet) {
	// fs.StringVar(&p.ImageRepo, "pebble-image-repo", "", "The container image repository for pebble to use in e2e tests")
	// fs.StringVar(&p.ImageTag, "pebble-image-tag", "", "The container image tag for pebble to use in e2e tests")
}

func (p *Pebble) Validate() []error {
	return nil
}
