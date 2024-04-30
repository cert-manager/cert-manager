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

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path"

	"github.com/onsi/ginkgo/v2"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
)

var cfg = framework.DefaultConfig

// isGinkgoProcessNumberOne is true if this is the first ginkgo process to run.
// Only the first ginkgo process will run the global addon Setup, Provision &
// Deprovision code.
// All other ginkgo processes will only run the global addon Setup code using
// the data transferred from the Setup function on the first ginkgo process.
var isGinkgoProcessNumberOne = false

var _ = ginkgo.SynchronizedBeforeSuite(func(ctx context.Context) []byte {
	addon.InitGlobals(cfg)

	isGinkgoProcessNumberOne = true

	// We first setup the global addons, but do not provision them yet.
	// This is because we need to transfer the data from ginkgo process #1
	// to the other ginkgo processes.
	toBeTransferred, err := addon.SetupGlobalsPrimary(cfg)
	if err != nil {
		framework.Failf("Error provisioning global addons: %v", err)
	}

	encodedData, err := json.Marshal(toBeTransferred)
	if err != nil {
		framework.Failf("Error encoding global addon data: %v", err)
	}

	return encodedData
}, func(ctx context.Context, encodedData []byte) {
	transferredData := []addon.AddonTransferableData{}
	err := json.Unmarshal(encodedData, &transferredData)
	if err != nil {
		framework.Failf("Error decoding global addon data: %v", err)
	}

	if isGinkgoProcessNumberOne {
		// For ginkgo process #1, we need to run ProvisionGlobals to
		// actually provision the global addons.
		err = addon.ProvisionGlobals(ctx, cfg)
		if err != nil {
			framework.Failf("Error configuring global addons: %v", err)
		}
	} else {
		// For gingko process #2 and above, we need to run Setup with
		// the Setup data returned by ginkgo process #1.
		addon.InitGlobals(cfg)

		err := addon.SetupGlobalsNonPrimary(cfg, transferredData)
		if err != nil {
			framework.Failf("Error provisioning global addons: %v", err)
		}
	}
})

var _ = ginkgo.SynchronizedAfterSuite(func(ctx context.Context) {
	// Reset the isGinkgoProcessNumberOne flag to false for the next run (when --repeat flag is used)
	isGinkgoProcessNumberOne = false
}, func(ctx context.Context) {
	ginkgo.By("Retrieving logs for global addons")
	globalLogs, err := addon.GlobalLogs()
	if err != nil {
		log.Logf("Failed to retrieve global addon logs: " + err.Error())
	}

	for k, v := range globalLogs {
		outPath := path.Join(cfg.Ginkgo.ReportDirectory, "logs", k)

		// Create a directory for the file if needed
		err := os.MkdirAll(path.Dir(outPath), 0755)
		if err != nil {
			log.Logf("Failed to create directory for logs: %v", err)
			continue
		}

		err = os.WriteFile(outPath, []byte(v), 0644)
		if err != nil {
			log.Logf("Failed to write log file: %v", err)
			continue
		}
	}

	ginkgo.By("Cleaning up the provisioned globals")
	err = addon.DeprovisionGlobals(ctx, cfg)
	if err != nil {
		framework.Failf("Error deprovisioning global addons: %v", err)
	}
})
