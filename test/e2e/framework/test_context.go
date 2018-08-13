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

package framework

import (
	"flag"
	"os"

	"github.com/onsi/ginkgo/config"

	"k8s.io/client-go/tools/clientcmd"
)

const (
	RecommendedConfigPathEnvVar = "CERTMANAGERCONFIG"
)

type TestContextType struct {
	KubeHost    string
	KubeConfig  string
	KubeContext string

	CertManagerHost    string
	CertManagerConfig  string
	CertManagerContext string

	PebbleImageRepo string
	PebbleImageTag  string
	ACMEURL         string

	ReportDir string
}

var TestContext TestContextType

// Register flags common to all e2e test suites.
func RegisterCommonFlags() {
	// Turn on verbose by default to get spec names
	config.DefaultReporterConfig.Verbose = true

	// Turn on EmitSpecProgress to get spec progress (especially on interrupt)
	config.GinkgoConfig.EmitSpecProgress = true

	// Randomize specs as well as suites
	config.GinkgoConfig.RandomizeAllSpecs = true

	flag.StringVar(&TestContext.KubeHost, "kubernetes-host", "http://127.0.0.1:8080", "The kubernetes host, or apiserver, to connect to")
	flag.StringVar(&TestContext.KubeConfig, "kubernetes-config", os.Getenv(clientcmd.RecommendedConfigPathEnvVar), "Path to config containing embedded authinfo for kubernetes. Default value is from environment variable "+clientcmd.RecommendedConfigPathEnvVar)
	flag.StringVar(&TestContext.KubeContext, "kubernetes-context", "", "config context to use for kuberentes. If unset, will use value from 'current-context'")
	flag.StringVar(&TestContext.CertManagerHost, "cert-manager-host", "http://127.0.0.1:30000", "The cert-manager host, or apiserver, to connect to")
	flag.StringVar(&TestContext.CertManagerConfig, "cert-manager-config", os.Getenv(RecommendedConfigPathEnvVar), "Path to config containing embedded authinfo for cert-manager. Default value is from environment variable "+RecommendedConfigPathEnvVar)
	flag.StringVar(&TestContext.CertManagerContext, "cert-manager-context", "", "config context to use for cert-manager. If unset, will use value from 'current-context'")
	flag.StringVar(&TestContext.PebbleImageRepo, "pebble-image-repo", "", "The container image repository for pebble to use in e2e tests")
	flag.StringVar(&TestContext.PebbleImageTag, "pebble-image-tag", "", "The container image tag for pebble to use in e2e tests")
	flag.StringVar(&TestContext.ACMEURL, "acme-url", "https://pebble.pebble.svc.cluster.local/dir", "The ACME test server to use in e2e tests")
	flag.StringVar(&TestContext.ReportDir, "report-dir", "", "Optional directory to store junit output in. If not specified, no junit file will be output")
}

func RegisterParseFlags() {
	RegisterCommonFlags()
	flag.Parse()
}
