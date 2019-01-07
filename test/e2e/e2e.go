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

package e2e

import (
	"github.com/onsi/ginkgo"

	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon"
)

var (
	cfg = framework.DefaultConfig
)

var _ = ginkgo.SynchronizedBeforeSuite(func() []byte {
	addon.InitGlobals(cfg)

	ginkgo.By("Provisioning shared cluster addons")

	err := addon.ProvisionGlobals(cfg)
	if err != nil {
		framework.Failf("Error provisioning global addons: %v", err)
	}

	return nil
}, func([]byte) {
	addon.InitGlobals(cfg)

	ginkgo.By("Configuring details for shared cluster addons")

	err := addon.SetupGlobals(cfg)
	if err != nil {
		framework.Failf("Error configuring global addons: %v", err)
	}
})

var globalLogs string

var _ = ginkgo.SynchronizedAfterSuite(func() {},
	func() {
		ginkgo.By("Retrieving logs for global addons")
		var err error
		globalLogs, err = addon.GlobalLogs()
		if err != nil {
			ginkgo.GinkgoWriter.Write([]byte("Failed to retrieve global addon logs: " + err.Error()))
		}

		ginkgo.By("Cleaning up the provisioned globals")
		err = addon.DeprovisionGlobals(cfg)
		if err != nil {
			framework.Failf("Error deprovisioning global addons: %v", err)
		}
	})
