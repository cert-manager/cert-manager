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
	"github.com/jetstack/cert-manager/hack/build/internal/consts"
	"github.com/spf13/pflag"
)

type CertManager struct {
	Components []string
	DockerRepo string
	AppVersion string
}

func (i *CertManager) AddFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&i.Components, "components", consts.CertManagerComponents, "list of cert-manager components to build")
	fs.StringVar(&i.DockerRepo, "docker-repo", consts.DefaultDockerRepo, "docker repository prefix to use for docker images")
	fs.StringVar(&i.AppVersion, "app-version", consts.DefaultAppVersion, "cert-manager version to tag images with")
}
