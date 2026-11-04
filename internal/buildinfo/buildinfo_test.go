/*
Copyright 2026 The cert-manager Authors.

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

package buildinfo

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/version"

	"github.com/cert-manager/cert-manager/pkg/util"
)

func setBuildFlags(t *testing.T, appVersion, gitCommit string) {
	oldVersion, oldCommit := util.AppVersion, util.AppGitCommit
	util.AppVersion, util.AppGitCommit = appVersion, gitCommit
	t.Cleanup(func() { util.AppVersion, util.AppGitCommit = oldVersion, oldCommit })
}

func expected(revision, appVersion string) string {
	return `
# HELP certmanager_build_info A metric with a constant '1' value labeled by version, revision, branch, goversion from which certmanager was built, and the goos and goarch for the build.
# TYPE certmanager_build_info gauge
certmanager_build_info{branch="",goarch="` + version.GoArch + `",goos="` + version.GoOS + `",goversion="` + version.GoVersion + `",revision="` + revision + `",tags="` + version.GetTags() + `",version="` + appVersion + `"} 1
`
}

func TestCollector(t *testing.T) {
	setBuildFlags(t, "v1.2.3", "abc123")

	if err := testutil.CollectAndCompare(NewCollector(), strings.NewReader(expected("abc123", "v1.2.3"))); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorWithoutGitCommit(t *testing.T) {
	setBuildFlags(t, "canary", "")

	c := NewCollector()
	revision := version.GetRevision()
	if revision == "" {
		t.Fatal("expected a fallback revision")
	}
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected(revision, "canary"))); err != nil {
		t.Fatal(err)
	}
}
