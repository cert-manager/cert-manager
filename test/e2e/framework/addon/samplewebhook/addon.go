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

package samplewebhook

import (
	"fmt"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/certmanager"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/chart"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
)

// CertmanagerWebhook defines an addon that installs a cert-manager DNS01
// webhook
type CertmanagerWebhook struct {
	config        *config.Config
	chart         *chart.Chart
	tillerDetails *tiller.Details

	// Tiller is the tiller instance used to deploy the chart
	Tiller *tiller.Tiller

	Certmanager *certmanager.Certmanager

	Name string

	// Required namespace to deploy the webhook into.
	Namespace string

	// Optional override for the group name to use for the webhook
	GroupName string
}

// Details return the details about the webhook instance deployed
type Details struct {
	GroupName  string
	SolverName string
}

func (p *CertmanagerWebhook) Setup(cfg *config.Config) error {
	p.config = cfg
	if p.Name == "" {
		return fmt.Errorf("name field must be set")
	}
	if p.Namespace == "" {
		return fmt.Errorf("namespace name must be specified")
	}
	if p.Tiller == nil {
		return fmt.Errorf("tiller field must be set")
	}
	if p.Certmanager == nil {
		return fmt.Errorf("certmanager field must be set")
	}
	if p.config.Kubectl == "" {
		return fmt.Errorf("path to kubectl must be provided")
	}
	if p.GroupName == "" {
		p.GroupName = p.Name + ".acme.example.com"
	}
	var err error
	p.tillerDetails, err = p.Tiller.Details()
	if err != nil {
		return err
	}
	p.chart = &chart.Chart{
		Tiller:      p.Tiller,
		ReleaseName: "wh-" + p.Name,
		Namespace:   p.Namespace,
		ChartName:   cfg.RepoRoot + "/test/e2e/framework/addon/samplewebhook/sample/chart/example-webhook",
		Vars: []chart.StringTuple{
			{Key: "certManager.namespace", Value: p.Certmanager.Namespace},
			{Key: "certManager.serviceAccountName", Value: p.Certmanager.Details().ServiceAccountName},
			{Key: "image.repository", Value: "sample-webhook"},
			{Key: "image.tag", Value: "bazel"},
			{Key: "groupName", Value: p.GroupName},
		},
		Values: []string{cfg.RepoRoot + "/test/fixtures/example-webhook-values.yaml"},
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
func (p *CertmanagerWebhook) Provision() error {
	return p.chart.Provision()
}

// Details returns details that can be used to utilise the instance of Pebble.
func (p *CertmanagerWebhook) Details() *Details {
	return &Details{
		GroupName:  p.GroupName,
		SolverName: "my-custom-solver",
	}
}

// Deprovision will destroy this instance of Pebble
func (p *CertmanagerWebhook) Deprovision() error {
	return p.chart.Deprovision()
}

func (p *CertmanagerWebhook) SupportsGlobal() bool {
	return false
}

func (p *CertmanagerWebhook) Logs() (map[string]string, error) {
	return p.chart.Logs()
}
