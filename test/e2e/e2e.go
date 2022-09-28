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
	"os"
	"path"

	"github.com/onsi/ginkgo/v2"

	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon"
	"github.com/cert-manager/cert-manager/test/e2e/framework/log"
)

var cfg = framework.DefaultConfig

var _ = ginkgo.SynchronizedBeforeSuite(func() []byte {
	addon.InitGlobals(cfg)

	err := addon.ProvisionGlobals(cfg)
	if err != nil {
		framework.Failf("Error provisioning global addons: %v", err)
	}

	return nil
}, func([]byte) {
	addon.InitGlobals(cfg)

	err := addon.SetupGlobals(cfg)
	if err != nil {
		framework.Failf("Error configuring global addons: %v", err)
	}
})

var _ = ginkgo.SynchronizedAfterSuite(func() {}, func() {
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
	err = addon.DeprovisionGlobals(cfg)
	if err != nil {
		framework.Failf("Error deprovisioning global addons: %v", err)
	}
})
