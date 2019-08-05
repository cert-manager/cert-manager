package util

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/go-logr/logr"

	"github.com/jetstack/cert-manager/hack/build/internal/exec"
)

// GitCommitRef returns the current commit reference for the repository
func GitCommitRef() (string, error) {
	var err error
	ref, err := gitOutput("rev-parse", "--short", "HEAD")
	if err != nil {
		return "", fmt.Errorf("error getting current commit ref: %v", err)
	}

	return ref, nil
}

func AppVersion(log logr.Logger, upstreamURL string) (string, error) {
	log.Info("fetching upstream git repo tags")
	_, err := gitOutput("fetch", "--tags", upstreamURL)
	if err != nil {
		return "", fmt.Errorf("error fetching tags: %v", err)
	}

	log.Info("finding tags that match the current commit ref")
	appVersion, err := gitOutput("describe", "--tags", "--abbrev=0", "--exact-match")
	if err != nil {
		log.Error(err, "failed to determine tag for current git ref, defaulting to v0.0.0-bazel")
		return "v0.0.0-bazel", nil
	}
	return appVersion, nil
}

func gitOutput(args ...string) (string, error) {
	stdout, stderr, err := exec.RunCommand(nil, "git", args...)
	if err != nil {
		return "", exec.FormatError(stdout, stderr, err)
	}

	b, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(b)), err
}
