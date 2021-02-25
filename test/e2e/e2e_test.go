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

package e2e

import (
	"flag"
	"fmt"
	"path"
	"testing"
	"time"

	"github.com/onsi/ginkgo"
	ginkgoconfig "github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/reporters"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	_ "github.com/cert-manager/cert-manager/test/e2e/suite"
)

func init() {
	logs.InitLogs(flag.CommandLine)
	framework.DefaultConfig.AddFlags(flag.CommandLine)

	// Turn on verbose by default to get spec names
	ginkgoconfig.DefaultReporterConfig.Verbose = true
	// Turn on EmitSpecProgress to get spec progress (especially on interrupt)
	ginkgoconfig.GinkgoConfig.EmitSpecProgress = true
	// Randomize specs as well as suites
	ginkgoconfig.GinkgoConfig.RandomizeAllSpecs = true

	wait.ForeverTestTimeout = time.Second * 60

}

func TestE2E(t *testing.T) {
	defer logs.FlushLogs()
	flag.Parse()

	// Disable skipped tests unless they are explicitly requested.
	// Copied from https://github.com/kubernetes/kubernetes/blob/960e5e78255dd148d4dae49f62e729ea940f4f07/test/e2e/e2e.go#L103-L106
	// See https://github.com/kubernetes/community/blob/master/contributors/devel/sig-testing/flaky-tests.md#quarantining-flakes
	if ginkgoconfig.GinkgoConfig.FocusString == "" && ginkgoconfig.GinkgoConfig.SkipString == "" {
		ginkgoconfig.GinkgoConfig.SkipString = `\[Flaky\]|\[Feature:.+\]`
	}

	if err := framework.DefaultConfig.Validate(); err != nil {
		t.Fatalf("Invalid test config: %v", err)
	}

	gomega.NewWithT(t)
	gomega.RegisterFailHandler(ginkgo.Fail)

	// TODO: properly make use of default SkipString
	// Disable skipped tests unless they are explicitly requested.
	// if ginkgoconfig.GinkgoConfig.FocusString == "" && ginkgoconfig.GinkgoConfig.SkipString == "" {
	// 	ginkgoconfig.GinkgoConfig.SkipString = `\[Flaky\]|\[Feature:.+\]`
	// }

	var r []ginkgo.Reporter
	if framework.DefaultConfig.Ginkgo.ReportDirectory != "" {
		r = append(r, reporters.NewJUnitReporter(path.Join(framework.DefaultConfig.Ginkgo.ReportDirectory,
			fmt.Sprintf("junit_%s_%02d.xml",
				framework.DefaultConfig.Ginkgo.ReportPrefix,
				ginkgoconfig.GinkgoConfig.ParallelNode))))
	}

	ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "cert-manager e2e suite", r)
}
