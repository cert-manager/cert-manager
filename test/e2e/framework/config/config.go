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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/clientcmd"

	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

var featureGates string

type Config struct {
	KubeConfig  string
	KubeContext string
	Kubectl     string

	// If Cleanup is true, addons will be cleaned up both before and after provisioning
	Cleanup bool

	// RepoRoot is used as the base path for any parts of the framework that
	// require access to repo files, such as Helm charts and test fixtures.
	RepoRoot string

	Ginkgo Ginkgo
	Addons Addons
	Suite  Suite
}

func (c *Config) Validate() error {
	var errs []error
	if c.KubeConfig == "" {
		errs = append(errs, fmt.Errorf("--kubernetes-config must be specified"))
	}
	if c.RepoRoot == "" {
		errs = append(errs, fmt.Errorf("--repo-root must be specified"))
	}

	errs = append(errs, c.Ginkgo.Validate()...)
	errs = append(errs, c.Addons.Validate()...)
	errs = append(errs, c.Suite.Validate()...)

	// Apply feature gate flag on the actual shared feature gate map using a
	// pflag set with the copied value.
	ps := pflag.NewFlagSet("", pflag.ContinueOnError)
	utilfeature.DefaultMutableFeatureGate.AddFlag(ps)
	if err := ps.Parse([]string{"--feature-gates=" + flag.CommandLine.Lookup("feature-gates").Value.String()}); err != nil {
		errs = append(errs, fmt.Errorf("failed to parse --feature-gates flag: %w", err))
	}

	return utilerrors.NewAggregate(errs)
}

// Register flags common to all e2e test suites.
func (c *Config) AddFlags(fs *flag.FlagSet) {
	kubeConfigFile := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if kubeConfigFile == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			panic("Failed to get user home directory: " + err.Error())
		}
		kubeConfigFile = filepath.Join(homeDir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
	}
	// Kubernetes API server config
	fs.StringVar(&c.KubeConfig, "kubernetes-config", kubeConfigFile, "Path to config containing embedded authinfo for kubernetes. Default value is from environment variable "+clientcmd.RecommendedConfigPathEnvVar)
	fs.StringVar(&c.KubeContext, "kubernetes-context", "", "config context to use for kubernetes. If unset, will use value from 'current-context'")
	fs.StringVar(&c.Kubectl, "kubectl-path", "kubectl", "path to the kubectl binary to use during e2e tests.")
	fs.BoolVar(&c.Cleanup, "cleanup", true, "If true, addons will be cleaned up both before and after provisioning")

	// TODO: get rid of this variable by bundling required files as part of test suite
	fs.StringVar(&c.RepoRoot, "repo-root", "", "Path to the root of the repository, used for access to repo-homed test fixtures.")

	// Register own feature gates flag since component-base uses pflag and we are
	// using flag stdlib.
	fs.StringVar(&featureGates, "feature-gates", "",
		"A set of key=value pairs that describe feature gates for alpha/experimental features. "+
			"Options are:\n"+strings.Join(utilfeature.DefaultMutableFeatureGate.KnownFeatures(), ", ")+"\n")

	c.Ginkgo.AddFlags(fs)
	c.Addons.AddFlags(fs)
	c.Suite.AddFlags(fs)
}
