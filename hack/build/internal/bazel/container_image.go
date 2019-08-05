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

package bazel

import (
	"context"
	"fmt"
	"github.com/jetstack/cert-manager/hack/build/internal/exec"
	"io"
	"strings"

	"github.com/go-logr/logr"
)

// ContainerImage provides a library for interacting with Bazel container_image
// targets.
// This includes building targets for multiple platforms as well as exporing
// targets to the local Docker daemon.
// It does not currently work with 'external' targets.
// If you need to interact with an external target, you should instead wrap the
// image in another container_image that is defined in your own workspace.

type ContainerImage struct {
	// BazelBinaryPath is the path to the bazel binary.
	// If not set, 'bazel' will be used and the binary will be looked up using
	// the configured $PATH.
	BazelBinaryPath string

	// Target is the bazel target for the container image that this rule wraps
	// in Bazel Label notation, for example "//cmd/controller:image".
	Target string

	// EnvVars is an optional map of strings that will be set as environment
	// variables when running the Bazel command.
	// This is useful for setting 'stamp' variables used in builds.
	EnvVars map[string]string

	// WorkspaceDir is the path to the root of the Bazel repository.
	// If not set, the current working directory will be used.
	// This directory will be cd'd into whenever any Bazel commands are run.
	WorkspaceDir string

	// OS is the operating system to build for, e.g. 'linux'
	OS string

	// Arch is the architecture to build for, e.g. 'amd64'
	Arch string

	// Stdout is an optional Writer that can be specified to capture output
	// from kind.
	// If not specified, output will be returned as part of the 'error' from
	// the Execute function.
	Stdout io.Writer

	// Log is an optional logr which will be used for debug logging.
	Log logr.InfoLogger
}

func (c *ContainerImage) Build(ctx context.Context) error {
	return c.bzl().BuildPlatformE(ctx, c.os(), c.arch(), c.Target)
}

func (c *ContainerImage) Export(ctx context.Context, imageNames ...string) error {
	if !strings.HasPrefix(c.Target, "//") {
		return fmt.Errorf("image targets must begin with // and exist in the current bazel workspace")
	}

	exportedImageName := "bazel/" + c.Target[2:len(c.Target)]
	if err := c.bzl().RunPlatformE(ctx, c.os(), c.arch(), c.Target); err != nil {
		return err
	}

	c.Log.Info("exported image with name", "image_name", exportedImageName)
	for _, n := range imageNames {
		c.Log.Info("tagging image", "new_name", n)
		if err := exec.FormatError(exec.RunCommand(c.Stdout, "docker", "tag", exportedImageName, n)); err != nil {
			return err
		}
		c.Log.Info("tagged image", "old_name", exportedImageName, "new_name", n)
	}

	return nil
}

func (c *ContainerImage) os() string {
	if c.OS == "" {
		return "linux"
	}
	return c.OS
}

func (c *ContainerImage) arch() string {
	if c.Arch == "" {
		return "amd64"
	}
	return c.Arch
}

func (c *ContainerImage) bzl() *Bazel {
	return &Bazel{
		BazelBinaryPath: c.BazelBinaryPath,
		WorkspaceDir:    c.WorkspaceDir,
		EnvVars:         c.EnvVars,
		Stdout:          c.Stdout,
		Log:             c.Log,
	}
}
