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

// package Pebble contains an addon that installs Pebble
package pebble

import (
	"fmt"

	"github.com/jetstack/cert-manager/test/e2e/framework/addon/chart"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
)

// Pebble describes the configuration details for an instance of Pebble
// deployed to the test cluster
type Pebble struct {
	config        *config.Config
	chart         *chart.Chart
	tillerDetails *tiller.Details

	// Tiller is the tiller instance used to deploy the chart
	Tiller *tiller.Tiller

	// Name is a unique name for this Pebble deployment
	Name string

	// Namespace is the namespace to deploy Pebble into
	Namespace string
}

type Details struct {
	// Host is the hostname that can be used to connect to Pebble
	Host string
}

func (p *Pebble) Setup(cfg *config.Config) error {
	if p.Name == "" {
		return fmt.Errorf("Name field must be set on Pebble addon")
	}
	if p.Namespace == "" {
		// TODO: in non-global instances, we could generate a new namespace just
		// for this addon to be used from.
		return fmt.Errorf("Namespace name must be specified")
	}
	if p.Tiller == nil {
		return fmt.Errorf("Tiller field must be set on Pebble addon")
	}
	var err error
	p.tillerDetails, err = p.Tiller.Details()
	if err != nil {
		return err
	}
	p.chart = &chart.Chart{
		Tiller:      p.Tiller,
		ReleaseName: "chart-pebble-" + p.Name,
		Namespace:   p.Namespace,
		ChartName:   cfg.RepoRoot + "/test/e2e/charts/pebble",
		// doesn't matter when installing from disk
		ChartVersion: "0",
	}
	err = p.chart.Setup(cfg)
	if err != nil {
		return err
	}
	return nil
}

// Provision will actually deploy this instance of Pebble to the cluster.
func (p *Pebble) Provision() error {
	return p.chart.Provision()
}

// Details returns details that can be used to utilise the instance of Pebble.
func (p *Pebble) Details() *Details {
	return &Details{
		Host: fmt.Sprintf("https://pebble.%s.svc.cluster.local/dir", p.Namespace),
	}
}

// Deprovision will destroy this instance of Pebble
func (p *Pebble) Deprovision() error {
	return p.chart.Deprovision()
}

func (p *Pebble) SupportsGlobal() bool {
	// Pebble does support a global configuration, as the 'usage details' for
	// it are deterministic (i.e. not a result of the call to helm install).
	return true
}

func (p *Pebble) Logs() (map[string]string, error) {
	return p.chart.Logs()
}
