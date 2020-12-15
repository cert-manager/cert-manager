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

package util

import (
	"testing"
)

func TestVersion(t *testing.T) {
	type testT struct {
		appGitCommit    string
		appGitState     string
		appVersion      string
		expectedVersion string
		description     string
	}
	tests := []testT{
		{
			appVersion:      "canary",
			expectedVersion: "canary",
			description:     "canary version with no commit hash and no git state",
		},
		{
			appVersion:      "canary",
			appGitCommit:    "abc123",
			expectedVersion: "canary-abc123",
			description:     "canary version with a commit hash and no git state",
		},
		{
			appVersion:      "canary",
			appGitState:     "dirty",
			expectedVersion: "canary (dirty)",
			description:     "canary version with no commit hash and a git state",
		},
		{
			appVersion:      "canary",
			appGitCommit:    "abc123",
			appGitState:     "dirty",
			expectedVersion: "canary-abc123 (dirty)",
			description:     "canary version with a commit hash and a git state",
		},
		{
			appVersion:      "v0.3.0",
			expectedVersion: "v0.3.0",
			description:     "semver version with no commit hash and no git state",
		},
		{
			appVersion:      "v0.3.0",
			appGitCommit:    "abc123",
			expectedVersion: "v0.3.0",
			description:     "semver version with a commit hash and no git state",
		},
		{
			appVersion:      "v0.3.0",
			appGitState:     "dirty",
			expectedVersion: "v0.3.0 (dirty)",
			description:     "semver version with no commit hash and a git state",
		},
		{
			appVersion:      "v0.3.0",
			appGitCommit:    "abc123",
			appGitState:     "dirty",
			expectedVersion: "v0.3.0 (dirty)",
			description:     "semver version with a commit hash and a git state",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(test testT) func(*testing.T) {
			AppGitCommit = test.appGitCommit
			AppGitState = test.appGitState
			AppVersion = test.appVersion
			return func(t *testing.T) {
				if versionString := version(); versionString != test.expectedVersion {
					t.Errorf("version() == %s but expected %s", versionString, test.expectedVersion)
				}
			}
		}(test))
	}
}
