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
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cert-manager/cert-manager/pkg/util"
)

// NewCollector returns a collector for the certmanager_build_info metric.
// The metric always has the value 1 and carries the version, git commit and Go
// version of the running binary as labels.
func NewCollector() prometheus.Collector {
	info := util.VersionInfo()
	return prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: "certmanager",
			Name:      "build_info",
			Help:      "A metric with a constant value of 1, labelled with the version, git commit and Go version cert-manager was built with.",
			ConstLabels: prometheus.Labels{
				"version":   info.GitVersion,
				"revision":  info.GitCommit,
				"goversion": info.GoVersion,
			},
		},
		func() float64 { return 1 },
	)
}

// Register registers the build info collector with r. It is not an error if
// the collector was already registered.
func Register(r prometheus.Registerer) error {
	err := r.Register(NewCollector())
	var are prometheus.AlreadyRegisteredError
	if errors.As(err, &are) {
		return nil
	}
	return err
}
