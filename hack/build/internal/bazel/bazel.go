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
	"io"
	"os"
	"os/exec"

	"github.com/go-logr/logr"

	internalexec "github.com/jetstack/cert-manager/hack/build/internal/exec"
)

const (
	DefaultBazelBinaryPath = "bazel"
)

type Bazel struct {
	// BazelBinaryPath is the path to the bazel binary.
	// If not set, 'bazel' will be used and the binary will be looked up using
	// the configured $PATH.
	BazelBinaryPath string

	// EnvVars is an optional map of strings that will be set as environment
	// variables when running the Bazel command.
	// This is useful for setting 'stamp' variables used in builds.
	EnvVars map[string]string

	// WorkspaceDir is the path to the root of the Bazel repository.
	// If not set, the current working directory will be used.
	// This directory will be cd'd into whenever any Bazel commands are run.
	WorkspaceDir string

	// Stdout is an optional Writer that can be specified to capture output
	// from kind.
	// If not specified, output will be returned as part of the 'error' from
	// the Execute function.
	Stdout io.Writer

	// Log is an optional logr which will be used for debug logging.
	Log logr.InfoLogger
}

func (g *Bazel) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	bazelPath := g.BazelBinaryPath
	if bazelPath == "" {
		bazelPath = DefaultBazelBinaryPath
	}
	cmd := exec.CommandContext(ctx, bazelPath, args...)
	cmd.Dir = g.WorkspaceDir
	cmd.Env = os.Environ()
	for k, v := range g.EnvVars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	g.Log.Info("set command environment variables", "env", cmd.Env)
	return cmd
}

// Build will construct a new exec.Cmd that will build the given targets.
// It will produce artifacts suitable for running on the current host OS.
// The --platforms flag *will not* be set.
func (g *Bazel) Build(ctx context.Context, targets ...string) *exec.Cmd {
	return g.Cmd(ctx, append([]string{"build"}, targets...)...)
}

// BuildPlatform will construct a new exec.Cmd that will build the given
// targets for the provided os and architecture.
// This is useful when producing cross-builds.
// Bazel's --platforms variable will be set automatically.
func (g *Bazel) BuildPlatform(ctx context.Context, os, arch string, targets ...string) *exec.Cmd {
	platform := fmt.Sprintf("--platforms=@io_bazel_rules_go//go/toolchain:%s_%s", os, arch)
	// Set --stamp=true when running a build to workaround issues introduced
	// in bazelbuild/rules_go#2110. For more information, see: https://github.com/bazelbuild/rules_go/pull/2110#issuecomment-508713878
	// We should be able to remove the `--stamp=true` arg once this has been fixed!
	return g.Cmd(ctx, append([]string{"build", platform, "--stamp=true"}, targets...)...)
}

// BuildE will build the given targets for the current host OS.
// The --platforms flag *will not* be set.
func (g *Bazel) BuildE(ctx context.Context, targets ...string) error {
	return internalexec.FormatError(internalexec.Run(g.Stdout, g.Build(ctx, targets...)))
}

// BuildPlatformE will build the given targets for the provided os and
// architecture.
// This is useful when producing cross-builds.
// Bazel's --platforms variable will be set automatically.
func (g *Bazel) BuildPlatformE(ctx context.Context, os, arch string, targets ...string) error {
	return internalexec.FormatError(internalexec.Run(g.Stdout, g.BuildPlatform(ctx, os, arch, targets...)))
}

// Run will construct a new exec.Cmd that will run the given targets
// It will produce artifacts suitable for running on the current host OS.
// The --platforms flag *will not* be set.
func (g *Bazel) Run(ctx context.Context, target string, args ...string) *exec.Cmd {
	return g.Cmd(ctx, append([]string{"run", target}, args...)...)
}

// RunPlatform will construct a new exec.Cmd that will build the given
// target for the provided os and architecture.
// This is useful when producing cross-builds.
// Bazel's --platforms variable will be set automatically.
func (g *Bazel) RunPlatform(ctx context.Context, os, arch, target string, args ...string) *exec.Cmd {
	platform := fmt.Sprintf("--platforms=@io_bazel_rules_go//go/toolchain:%s_%s", os, arch)
	return g.Cmd(ctx, append([]string{"run", platform, "--stamp=true", target}, args...)...)
}

// RunE will run the given targets on the current host OS.
// The --platforms flag *will not* be set.
func (g *Bazel) RunE(ctx context.Context, target string, args ...string) error {
	return internalexec.FormatError(internalexec.Run(g.Stdout, g.Run(ctx, target, args...)))
}

// RunPlatformE will run the given target, built for the provided os and
// architecture.
// This is useful when producing cross-builds.
// Bazel's --platforms variable will be set automatically.
func (g *Bazel) RunPlatformE(ctx context.Context, os, arch, target string, args ...string) error {
	return internalexec.FormatError(internalexec.Run(g.Stdout, g.RunPlatform(ctx, os, arch, target, args...)))
}
