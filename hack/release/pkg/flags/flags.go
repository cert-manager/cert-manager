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

package flags

import (
	"fmt"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
	"os/exec"

	logf "github.com/jetstack/cert-manager/hack/release/pkg/log"
	"github.com/jetstack/cert-manager/hack/release/pkg/util"
)

var (
	Default = &Global{}

	log = logf.Log.WithName("global")
)

type Global struct {
	// Path to the root of the cert-manager repository
	RepoRoot string

	// DockerRepo is the docker repository used to store release images
	DockerRepo string

	// UpstreamRepoURL is the URL of the git repo used to check for tags
	UpstreamRepoURL string

	// AppVersion is the version tag to use for this release
	AppVersion string

	// GitState contains the state of the git working tree.
	GitState string

	// GitCommitRef is the current git commit hash being built
	GitCommitRef string

	GitPath string

	// Path to the cert-manager Helm chart.
	// This is defined as a global as the manifests plugin also needs
	// access to this flag
	ChartPath string
}

const defaultDockerRepo = "quay.io/jetstack"

func (g *Global) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&g.RepoRoot, "repo-root", "", "path to the root of the cert-manager repository")
	fs.StringVar(&g.DockerRepo, "docker-repo", defaultDockerRepo, "the docker repository that images will be tagged with")
	fs.StringVar(&g.AppVersion, "app-version", "", "app version to use when building and generating manifests. Defaults to 'git describe --tags --abbrev=0 --exact-match'")
	fs.StringVar(&g.UpstreamRepoURL, "git.upstream-repo-url", "https://github.com/jetstack/cert-manager.git", "the URL of the git repo used to check for tags when generating --app-version")
	fs.StringVar(&g.GitState, "git.state", "", "the state of the git working tree. if set and not 'clean', this will be appended to the app-version during builds")
	fs.StringVar(&g.GitCommitRef, "git.commit-ref", "", "the git commit ref of this build. Defaults to 'git rev-parse --short HEAD'")
	fs.StringVar(&g.GitPath, "git.path", "git", "path to the git binary to use")
	fs.StringVar(&g.ChartPath, "chart.path", "deploy/charts/cert-manager", "the path to the cert-manager helm chart, relative to the repo root")
}

func (g *Global) Validate() []error {
	var errs []error

	if g.UpstreamRepoURL == "" {
		errs = append(errs, fmt.Errorf("--git.upstream-repo-url must be specified"))
	}

	return errs
}

func (g *Global) Complete() error {
	log = log.WithName("default-flags")

	if g.DockerRepo == "" {
		log := log.WithValues("flag", "docker-repo")
		g.DockerRepo = defaultDockerRepo
		log.Info("set default value", "value", g.DockerRepo)
	}

	if g.RepoRoot == "" {
		log := log.WithValues("flag", "repo-root")
		if bwd := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); bwd != "" {
			g.RepoRoot = bwd
		} else {
			dir, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("error determining repo root: %v", err)
			}
			g.RepoRoot = dir
		}

		log.Info("set default value", "value", g.RepoRoot)
	}
	if err := os.Chdir(g.RepoRoot); err != nil {
		return fmt.Errorf("error changing directory to --repo-root=%q: %v", g.RepoRoot, err)
	}

	if g.AppVersion == "" {
		log := log.WithValues("flag", "app-version")

		log.V(logf.LogLevelDebug).Info("fetching upstream git repo tags")
		_, err := g.gitOutput("fetch", "--tags", g.UpstreamRepoURL)
		if err != nil {
			return fmt.Errorf("error fetching tags: %v", err)
		}

		log.V(logf.LogLevelDebug).Info("finding tags that match the current commit ref")
		g.AppVersion, err = g.gitOutput("describe", "--tags", "--abbrev=0", "--exact-match")
		if err != nil {
			log.Error(err, "failed to determine tag for current git ref/HEAD")
			g.AppVersion = ""
		}

		if g.AppVersion == "" {
			// default to 'v0.0.0-experimental' if no tags point to the current ref
			g.AppVersion = "v0.0.0-experimental"
		}

		log.WithValues("value", g.AppVersion).Info("set default value")
	}

	if g.GitCommitRef == "" {
		log := log.WithValues("flag", "git.commit-ref")

		log.V(logf.LogLevelDebug).Info("parsing current git commit ref")
		var err error
		g.GitCommitRef, err = g.gitOutput("rev-parse", "--short", "HEAD")
		if err != nil {
			return fmt.Errorf("error getting current commit ref: %v", err)
		}

		log.WithValues("value", g.GitCommitRef).Info("set default value")
	}

	if g.GitState == "" {
		log := log.WithValues("flag", "git.commit-state")

		log.V(logf.LogLevelDebug).Info("evaluating current git working tree dirty status")
		changes, err := g.gitOutput("status", "--porcelain")
		if err != nil {
			return fmt.Errorf("error checking git status: %v", err)
		}

		if len(changes) == 0 {
			g.GitState = "clean"
		} else {
			g.GitState = "dirty"
		}

		log.WithValues("value", g.GitState).Info("set default value")
	}

	return nil
}

func (g *Global) gitOutput(args ...string) (string, error) {
	cmd := exec.Command(g.GitPath, args...)
	b, err := util.RunPrintCombined(log, cmd)
	return strings.TrimSpace(string(b)), err
}
