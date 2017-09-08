/*
Copyright 2015 The Kubernetes Authors.
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

package e2e

import (
	"flag"
	"testing"

	"github.com/golang/glog"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/jetstack-experimental/cert-manager/test/e2e/framework"
)

var certManagerImageFlag string
var certManagerImagePullPolicy string

func init() {
	flag.StringVar(&certManagerImageFlag, "cert-manager-image", "jetstackexperimental/cert-manager-controller:canary",
		"The container image for cert-manager to test against")
	flag.StringVar(&certManagerImagePullPolicy, "cert-manager-image-pull-policy", "Never",
		"The image pull policy to use for cert-manager when running tests")

	framework.RegisterParseFlags()

	if "" == framework.TestContext.KubeConfig {
		glog.Fatalf("environment variable %v must be set", clientcmd.RecommendedConfigPathEnvVar)
	}
	if "" == framework.TestContext.CertManagerConfig {
		glog.Fatalf("environment variable %v must be set", framework.RecommendedConfigPathEnvVar)
	}
}

func TestE2E(t *testing.T) {
	RunE2ETests(t)
}
