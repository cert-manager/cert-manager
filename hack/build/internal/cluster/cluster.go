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

package cluster

import (
	"io"
	"io/ioutil"
	"strings"

	"github.com/go-logr/logr"

	"github.com/jetstack/cert-manager/hack/build/internal/exec"
)

const (
	DefaultKindClusterName = "cert-manager-cluster"
)

// Cluster allows creating, deleting and interacting with kind clusters.
type Cluster struct {
	// KindClusterName is an optional override for the name of the cluster that
	// the provisioner will create.
	// If not set, DefaultKindClusterName will be used.
	KindClusterName string

	// KindConfigPath is an optional path to a Kind config file.
	// If not specified, the default is no configuration file.
	KindConfigPath string

	// KindImage is the image name used to boot the kind cluster.
	// If not specified, none will be set and the default image for the kind
	// version used will be used.
	KindImage string

	// Executor is used to execute the kind command.
	// This is defined as an interface to allow executing kind with bazel or
	// with a binary.
	// If not specified, ExecutorBazel will be used.
	Executor Executor

	// Stdout is an optional Writer that can be specified to capture output
	// from kind.
	// If not specified, output will be returned as part of the 'error' from
	// the Execute function.
	Stdout io.Writer

	// Log is an optional logr which will be used for debug logging.
	Log logr.InfoLogger
}

// Create will create the cluster
func (c *Cluster) Create() error {
	args := []string{"create", "cluster"}
	if c.KindConfigPath != "" {
		args = append(args, "--config", c.KindConfigPath)
	}
	if c.KindImage != "" {
		args = append(args, "--image", c.KindImage)
	}
	return exec.FormatError(c.runKind(args...))
}

// Delete will delete the cluster
func (c *Cluster) Delete() error {
	return exec.FormatError(c.runKind("delete", "cluster"))
}

// Load will load the image with the given name into the kind docker daemon
func (c *Cluster) Load(image string) error {
	return exec.FormatError(c.runKind("load", "docker-image", image))
}

func (c *Cluster) KubeConfig() (string, error) {
	stdout, stderr, err := c.runKind("get", "kubeconfig-path")
	if err != nil {
		return "", exec.FormatError(stdout, stderr, err)
	}

	stdoutBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "", err
	}
	stdoutStr := string(stdoutBytes)
	stdoutStr = strings.TrimSpace(stdoutStr)
	return stdoutStr, nil
}

func (c *Cluster) runKind(args ...string) (stdout, stderr io.Reader, err error) {
	clusterName := c.KindClusterName
	if clusterName == "" {
		clusterName = DefaultKindClusterName
	}
	args = append(args, "--name", clusterName)

	executor := c.Executor
	if executor == nil {
		executor = ExecutorBazel
	}

	c.Log.Info("Running kind command", "args", args)
	return executor(c.Stdout, args...)
}

// Executor is a function that executes kind.
type Executor func(out io.Writer, args ...string) (stdout, stderr io.Reader, err error)

// ExecutorBinary executes kind by using the regular system PATH.
// It requires kind to be manually installed and made available ahead of time.
func ExecutorBinary(out io.Writer, args ...string) (stdout, stderr io.Reader, err error) {
	return exec.RunCommand(out, "kind", args...)
}

// ExecutorBazel executes kind using the //hack/bin:kind bazel target
func ExecutorBazel(out io.Writer, args ...string) (stdout, stderr io.Reader, err error) {
	completeArgs := append([]string{"run", "//hack/bin:kind", "--"}, args...)
	return exec.RunCommand(out, "bazel", completeArgs...)
}
