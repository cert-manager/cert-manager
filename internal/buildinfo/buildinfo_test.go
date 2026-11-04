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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/cert-manager/cert-manager/pkg/util"
)

func TestCollector(t *testing.T) {
	info := util.VersionInfo()
	expected := `
# HELP certmanager_build_info A metric with a constant value of 1, labelled with the version, git commit and Go version cert-manager was built with.
# TYPE certmanager_build_info gauge
certmanager_build_info{goversion="` + info.GoVersion + `",revision="` + info.GitCommit + `",version="` + info.GitVersion + `"} 1
`
	if err := testutil.CollectAndCompare(NewCollector(), strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterTwice(t *testing.T) {
	r := prometheus.NewRegistry()
	for range 2 {
		if err := Register(r); err != nil {
			t.Fatal(err)
		}
	}
}
