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

// package nginx contains an addon that installs nginx-ingress
package nginxingress

import (
	"fmt"

	cmutil "github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/chart"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
)

// Nginx describes the configuration details for an instance of nginx-ingress
// deployed to a cluster.
type Nginx struct {
	config        *config.Config
	chart         *chart.Chart
	tillerDetails *tiller.Details

	// Name is a unique name for this nginx-ingress deployment
	Name string

	// Namespace is the namespace to deploy nginx into
	Namespace string

	// Tiller is the tiller instance used to deploy the chart
	Tiller *tiller.Tiller

	// IPAddress is the IP address that the nginx-ingress service will be
	// exposed on.
	// This must be a part of the service CIDR, and must not already be allocated
	// else provisioning will fail.
	IPAddress string

	// Domain is a domain name that can be used during e2e tests.
	// This domain should have records for *.example.com and example.com pointing
	// to the IP listed above.
	Domain string
}

type Details struct {
	// BaseDomain is a domain name that can be used during e2e tests.
	// This domain should have records for *.example.com and example.com pointing
	// to the IP listed above.
	BaseDomain string

	// IngressClass configured for this controller
	IngressClass string
}

func (n *Nginx) Setup(cfg *config.Config) error {
	if n.Name == "" {
		return fmt.Errorf("Name field must be set on nginx addon")
	}
	if n.Namespace == "" {
		// TODO: in non-global instances, we could generate a new namespace just
		// for this addon to be used from.
		return fmt.Errorf("Namespace name must be specified")
	}
	if n.Tiller == nil {
		return fmt.Errorf("Tiller field must be set on nginx addon")
	}
	if n.IPAddress == "" {
		return fmt.Errorf("Nginx service IP address must be provided")
	}
	if n.Domain == "" {
		return fmt.Errorf("Nginx service domain must be provided")
	}
	var err error
	n.tillerDetails, err = n.Tiller.Details()
	if err != nil {
		return err
	}
	n.chart = &chart.Chart{
		Tiller:       n.Tiller,
		ReleaseName:  "chart-nginx-" + n.Name,
		Namespace:    n.Namespace,
		ChartName:    "stable/nginx-ingress",
		ChartVersion: cfg.Addons.Nginx.ChartVersion,
		Vars: []chart.StringTuple{
			{
				Key:   "controller.image.pullPolicy",
				Value: "Never",
			},
			{
				Key:   "controller.image.tag",
				Value: "0.23.0",
			},
			{
				Key:   "defaultBackend.image.pullPolicy",
				Value: "Never",
			},
			{
				Key:   "defaultBackend.image.tag",
				Value: "bazel",
			},
			{
				Key:   "controller.service.clusterIP",
				Value: n.IPAddress,
			},
			{
				Key:   "controller.service.type",
				Value: "ClusterIP",
			},
			// nginx-ingress will by default not redirect http to https if
			// the url is ".well-known"
			{
				Key:   "controller.config.no-tls-redirect-locations",
				Value: "",
			},
		},
	}
	err = n.chart.Setup(cfg)
	if err != nil {
		return err
	}
	return nil
}

// Provision will actually deploy this instance of nginx-ingress to the cluster.
func (n *Nginx) Provision() error {
	return n.chart.Provision()
}

// Details returns details that can be used to utilise the instance of nginx ingress.
func (n *Nginx) Details() *Details {
	return &Details{
		BaseDomain:   n.Domain,
		IngressClass: "nginx",
	}
}

// Deprovision will destroy this instance of nginx-ingress
func (n *Nginx) Deprovision() error {
	return n.chart.Deprovision()
}

// SupportsGlobal will return whether this addon supports having a global,
// shared instance deployed.
// In order for an addon to support 'global mode', the Config() *must* be able
// to be derived from the inputs to the addon only, i.e. there must be no state
// created by Provision that is required for the output of Config().
// This is because multiple test processes are started in order to run tests
// in parallel, and only one invocation (the 'root') will actually call the
// Provision function.
// Tests themselves will only call the Details() function.
func (n *Nginx) SupportsGlobal() bool {
	// nginx does support a global configuration, as the 'usage details' for
	// it are deterministic (i.e. not a result of the call to helm install).
	return true
}

func (n *Nginx) Logs() (map[string]string, error) {
	return n.chart.Logs()
}

func (d *Details) NewTestDomain() string {
	return fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), d.BaseDomain)
}
