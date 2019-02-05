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

package addon

import (
	"fmt"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/test/e2e/framework/addon/base"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/certmanager"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/nginxingress"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

type Addon interface {
	Setup(*config.Config) error
	Provision() error
	Deprovision() error
	SupportsGlobal() bool
}

// This file is used to define global shared addon instances for the e2e suite.
// We have to define these somewhere that can be imported by the framework and
// also the tests, so that we can provision them in SynchronizedBeforeSuit
// and access their config during tests.

var (
	// Base is a base addon containing Kubernetes clients
	Base = &base.Base{}
	// Tiller is a shared tiller addon
	Tiller = &tiller.Tiller{}
	// NginxIngress installs nginx-ingress as a helm chart
	NginxIngress = &nginxingress.Nginx{}
	// Certmanager install cert-manager as a helm chart
	CertManager = &certmanager.Certmanager{}

	// allAddons is populated by InitGlobals and defines the order in which
	// addons will be provisioned
	allAddons []Addon

	// provisioned is used internally to track which addons have been provisioned
	provisioned []Addon
)

var globalsInited = false

// InitGlobals actually allocates the addon values that are defined above.
// We do this here so that we can access the suites config structure during
// the definition of global addons.
func InitGlobals(cfg *config.Config) {
	if globalsInited {
		return
	}
	globalsInited = true
	*Base = base.Base{}
	*Tiller = tiller.Tiller{
		Base:               Base,
		Name:               "tiller-deploy",
		Namespace:          "cm-e2e-global-tiller-deploy",
		ClusterPermissions: true,
	}
	*NginxIngress = nginxingress.Nginx{
		Tiller:    Tiller,
		Name:      "nginx-ingress",
		Namespace: "cm-e2e-global-nginx-ingress",
		IPAddress: cfg.Addons.Nginx.Global.IPAddress,
		Domain:    cfg.Addons.Nginx.Global.Domain,
	}
	*CertManager = certmanager.Certmanager{
		Tiller:    Tiller,
		Name:      "cert-manager",
		Namespace: "cm-e2e-global-cert-manager",
	}
	allAddons = []Addon{
		Base,
		Tiller,
		CertManager,
		NginxIngress,
	}
}

// ProvisionGlobals provisions all of the global addons, including calling Setup.
// This should be called by the test suite entrypoint in a SynchronizedBeforeSuite
// block to ensure it is run once per suite.
func ProvisionGlobals(cfg *config.Config) error {
	// TODO: if we want to provision dependencies in parallel we will need
	// to improve the logic here.
	for _, g := range allAddons {
		if err := provisionGlobal(g, cfg); err != nil {
			return err
		}
	}
	return nil
}

// SetupGlobals will call Setup on all of the global addons, but not provision.
// This should be called by the test suite entrypoint in a BeforeSuite block
// on all ginkgo nodes to ensure global instances are configured for each test
// runner.
func SetupGlobals(cfg *config.Config) error {
	for _, g := range allAddons {
		err := g.Setup(cfg)
		if err != nil {
			return err
		}
	}
	return nil
}

type loggableAddon interface {
	Logs() (map[string]string, error)
}

func GlobalLogs() (map[string]string, error) {
	out := make(map[string]string)
	for _, p := range provisioned {
		p, ok := p.(loggableAddon)
		if !ok {
			continue
		}

		l, err := p.Logs()
		if err != nil {
			return nil, err
		}

		// TODO: namespace logs from each addon to their addon type to avoid
		// conflicts. Realistically, it's unlikely a conflict will occur though
		// so this will probably be fine for now.
		for k, v := range l {
			out[k] = v
		}
	}
	return out, nil
}

// DeprovisionGlobals deprovisions all of the global addons.
// This should be called by the test suite in a SynchronizedAfterSuite to ensure
// all global addons are cleaned up after a run.
func DeprovisionGlobals(cfg *config.Config) error {
	if !cfg.Cleanup {
		log.Logf("Skipping deprovisioning as cleanup set to false.")
		return nil
	}
	var errs []error
	// deprovision addons in the reverse order to that of provisioning
	for i := len(provisioned) - 1; i >= 0; i-- {
		a := provisioned[i]
		errs = append(errs, a.Deprovision())
	}
	return utilerrors.NewAggregate(errs)
}

func provisionGlobal(a Addon, cfg *config.Config) error {
	if err := a.Setup(cfg); err != nil {
		return err
	}
	if !a.SupportsGlobal() {
		return fmt.Errorf("Requested global plugin does not support shared mode with current configuration")
	}
	if cfg.Cleanup {
		err := a.Deprovision()
		if err != nil {
			return err
		}
	}
	provisioned = append(provisioned, a)
	if err := a.Provision(); err != nil {
		return err
	}
	return nil
}
