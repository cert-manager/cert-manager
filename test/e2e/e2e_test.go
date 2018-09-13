/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	"testing"
	"time"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/jetstack/cert-manager/test/e2e/framework"
)

func init() {
	framework.RegisterParseFlags()

	wait.ForeverTestTimeout = time.Second * 60

	if "" == framework.TestContext.KubeConfig {
		glog.Fatalf("environment variable %v must be set", clientcmd.RecommendedConfigPathEnvVar)
	}
	if "" == framework.TestContext.CertManagerConfig {
		glog.Fatalf("environment variable %v must be set", framework.RecommendedConfigPathEnvVar)
	}
	if "" == framework.TestContext.ACMEURL {
		glog.Fatalf("flag -acme-url must be set")
	}
}

func TestE2E(t *testing.T) {
	RunE2ETests(t)
}
