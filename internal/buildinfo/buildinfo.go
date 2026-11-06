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

// Package buildinfo provides the certmanager_build_info metric, which
// identifies the version of the running cert-manager component.
package buildinfo

import (
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/common/version"

	"github.com/cert-manager/cert-manager/pkg/util"
)

// NewCollector returns the client_golang version collector for the
// certmanager_build_info metric, with the version and git commit cert-manager
// was built with. Without a git commit from the build flags, the revision falls
// back to the VCS information embedded by the Go toolchain.
func NewCollector() prometheus.Collector {
	version.Version = util.AppVersion
	version.Revision = util.AppGitCommit
	return versioncollector.NewCollector("certmanager")
}
