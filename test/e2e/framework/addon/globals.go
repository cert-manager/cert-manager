/*
Copyright 2020 The cert-manager Authors.

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
	"context"
	"fmt"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/base"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/internal"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/vault"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/config"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
)

type Addon = internal.Addon
type AddonTransferableData = internal.AddonTransferableData

// This file is used to define global shared addon instances for the e2e suite.
// We have to define these somewhere that can be imported by the framework and
// also the tests, so that we can provision them in SynchronizedBeforeSuit
// and access their config during tests.

var (
	// Base is a base addon containing Kubernetes clients
	Base             = &base.Base{}
	Vault            = &vault.Vault{}
	VaultEnforceMtls = &vault.Vault{}

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
	*Vault = vault.Vault{
		Base:      Base,
		Namespace: "e2e-vault",
		Name:      "vault",
	}
	*VaultEnforceMtls = vault.Vault{
		Base:        Base,
		Namespace:   "e2e-vault-mtls",
		Name:        "vault-mtls",
		EnforceMtls: true,
	}
	allAddons = []Addon{
		Base,
		Vault,
		VaultEnforceMtls,
	}
}

// SetupGlobals setups all of the global addons.
// The primary ginkgo process is the process with index 1.
// This function should be called by the test suite entrypoint in a SynchronizedBeforeSuite
// block to ensure it is run only on ginkgo process #1. It has to be run before
// any other ginkgo processes are started, because the return value of this function
// has to be transferred to the other ginkgo processes.
func SetupGlobalsPrimary(cfg *config.Config) ([]AddonTransferableData, error) {
	toBeTransferred := make([]AddonTransferableData, len(allAddons))
	for addonIdx, g := range allAddons {
		data, err := g.Setup(cfg)
		if err != nil {
			return nil, err
		}
		if !g.SupportsGlobal() {
			return nil, fmt.Errorf("requested global plugin does not support shared mode with current configuration")
		}
		toBeTransferred[addonIdx] = data
	}
	return toBeTransferred, nil
}

// SetupGlobalsNonPrimary setups all of the global addons.
// A non-primary ginkgo process is one that is not process #1 (process #2 and above).
// This function should be called by the test suite entrypoint in a SynchronizedBeforeSuite
// block on all ginkgo processes except #1. It has to be run after the primary process has
// run SetupGlobalsPrimary, so that the data returned by SetupGlobalsPrimary on process #1
// can be passed into this function. This function calls Setup on all of the non-primary
// processes (processes #2 and above) and passes in the AddonTransferableData data returned
// by the primary process.
func SetupGlobalsNonPrimary(cfg *config.Config, transferred []AddonTransferableData) error {
	for addonIdx, g := range allAddons {
		_, err := g.Setup(cfg, transferred[addonIdx])
		if err != nil {
			return err
		}
		if !g.SupportsGlobal() {
			return fmt.Errorf("requested global plugin does not support shared mode with current configuration")
		}
	}
	return nil
}

// ProvisionGlobals calls Provision on all of the global addons.
// This should be called by the test suite in a SynchronizedBeforeSuite block
// after the Setup data has been transferred to all ginkgo processes, so that
// not all processes have to wait for the addons to be provisioned. Instead,
// the individual test has to check that the addon is provisioned (eg. by querying
// the API server for a resource that the addon creates or by checking that an
// HTTP endpoint is available)
// This function should be run only on ginkgo process #1.
func ProvisionGlobals(ctx context.Context, cfg *config.Config) error {
	for _, g := range allAddons {
		provisioned = append(provisioned, g)
		if err := g.Provision(ctx); err != nil {
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
// all global addons are cleaned up after a run. This should be run only on ginkgo
// process #1.
func DeprovisionGlobals(ctx context.Context, cfg *config.Config) error {
	if !cfg.Cleanup {
		log.Logf("Skipping deprovisioning as cleanup set to false.")
		return nil
	}
	var errs []error
	// deprovision addons in the reverse order to that of provisioning
	for i := len(provisioned) - 1; i >= 0; i-- {
		a := provisioned[i]
		errs = append(errs, a.Deprovision(ctx))
	}
	return utilerrors.NewAggregate(errs)
}
