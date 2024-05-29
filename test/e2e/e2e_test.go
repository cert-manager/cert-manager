//go:build e2e_test

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
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"

	logf "github.com/cert-manager/cert-manager/pkg/logs"

	_ "github.com/cert-manager/cert-manager/e2e-tests/suite"
)

func init() {
	logf.InitLogs()
	cfg.AddFlags(flag.CommandLine)
	ctrl.SetLogger(logf.Log)

	wait.ForeverTestTimeout = time.Second * 60
}

func TestE2E(t *testing.T) {
	defer logf.FlushLogs()

	gomega.RegisterFailHandler(ginkgo.Fail)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Invalid test config: %v", err)
	}

	ginkgo.RunSpecs(t, "cert-manager e2e suite")
}
