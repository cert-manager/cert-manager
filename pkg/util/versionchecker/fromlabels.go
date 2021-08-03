/*
Copyright 2021 The cert-manager Authors.

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

package versionchecker

import (
	"regexp"
)

var helmChartVersion = regexp.MustCompile(`-(v(?:\d+)\.(?:\d+)\.(?:\d+)(?:.*))$`)

func extractVersionFromLabels(crdLabels map[string]string) string {
	if version, ok := crdLabels["app.kubernetes.io/version"]; ok {
		return version
	}

	if chartName, ok := crdLabels["helm.sh/chart"]; ok {
		version := helmChartVersion.FindStringSubmatch(chartName)
		if len(version) == 2 {
			return version[1]
		}
	}

	if chartName, ok := crdLabels["chart"]; ok {
		version := helmChartVersion.FindStringSubmatch(chartName)
		if len(version) == 2 {
			return version[1]
		}
	}

	return ""
}
