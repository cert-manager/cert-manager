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

package certmanager

import (
	"fmt"
	"os/exec"

	"github.com/jetstack/cert-manager/test/e2e/framework/addon/chart"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
)

// Certmanager defines an addon that installs an instance of certmanager in the
// target cluster.
// Currently, only one instance of Certmanager can be deployed in a single
// invocation of the test suite (i.e. it *must* be instantiated globally).
// In future we can restrict Certmanager to a single namespace in order to enforce
// isolation between tests.
type Certmanager struct {
	config        *config.Config
	chart         *chart.Chart
	tillerDetails *tiller.Details

	// Tiller is the tiller instance used to deploy the chart
	Tiller *tiller.Tiller

	Name string

	// Required namespace to deploy Certmanager into.
	Namespace string
}

// Details return the details about the certmanager instance deployed
type Details struct {
	ClusterResourceNamespace string
}

func (p *Certmanager) Setup(cfg *config.Config) error {
	p.config = cfg
	if p.Name == "" {
		return fmt.Errorf("Name field must be set on Certmanager addon")
	}
	if p.Namespace == "" {
		// TODO: in non-global instances, we could generate a new namespace just
		// for this addon to be used from.
		return fmt.Errorf("Namespace name must be specified")
	}
	if p.Tiller == nil {
		return fmt.Errorf("Tiller field must be set on Certmanager addon")
	}
	if p.config.Kubectl == "" {
		return fmt.Errorf("path to kubectl must be provided")
	}
	var err error
	p.tillerDetails, err = p.Tiller.Details()
	if err != nil {
		return err
	}
	p.chart = &chart.Chart{
		Tiller:      p.Tiller,
		ReleaseName: "chart-certmanager-" + p.Name,
		Namespace:   p.Namespace,
		ChartName:   cfg.RepoRoot + "/deploy/charts/cert-manager",
		// TODO: move resource requests/limits into Vars so they are always set
		Values: []string{cfg.RepoRoot + "/test/fixtures/cert-manager-values.yaml"},
		// doesn't matter when installing from disk
		ChartVersion: "0",
		UpdateDeps:   true,
	}
	err = p.chart.Setup(cfg)
	if err != nil {
		return err
	}
	return nil
}

// Provision will actually deploy this instance of Pebble-ingress to the cluster.
func (p *Certmanager) Provision() error {
	if err := exec.Command(p.config.Kubectl, "apply", "-f", p.config.RepoRoot+"/deploy/manifests/00-crds.yaml").Run(); err != nil {
		return fmt.Errorf("Error install cert-manager CRD manifests: %v", err)
	}

	return p.chart.Provision()
}

// Details returns details that can be used to utilise the instance of Pebble.
func (p *Certmanager) Details() *Details {
	return &Details{
		ClusterResourceNamespace: p.Namespace,
	}
}

// Deprovision will destroy this instance of Pebble
func (p *Certmanager) Deprovision() error {
	return p.chart.Deprovision()
}

func (p *Certmanager) SupportsGlobal() bool {
	// Pebble does support a global configuration, as the 'usage details' for
	// it are deterministic (i.e. not a result of the call to helm install).
	return true
}

func (p *Certmanager) Logs() (map[string]string, error) {
	return p.chart.Logs()
}
