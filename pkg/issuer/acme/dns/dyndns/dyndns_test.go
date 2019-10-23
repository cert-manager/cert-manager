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

package dyndns

import (
	"k8s.io/klog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	dynCustomerName string
	dynUsername     string
	dynPassword     string
	dynZoneName     string
	dynLiveTest     bool
)

func init() {

	klog.Info("Starting DynDNS test")

	dynUsername = os.Getenv("DYN_USERNAME")
	dynPassword = os.Getenv("DYN_PASSWORD")
	dynCustomerName = os.Getenv("DYN_CUSTOMER_NAME")
	dynZoneName = os.Getenv("DYN_ZONE_NAME")

	if len(dynCustomerName) > 0 && len(dynUsername) > 0 && len(dynPassword) > 0 && len(dynZoneName) > 0 {
		dynLiveTest = true
	}
}

func TestLiveDynDnsPresent(t *testing.T) {
	if !dynLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials(dynCustomerName, dynUsername, dynPassword, dynZoneName)
	assert.NoError(t, err)

	err = provider.Present(dynZoneName, "testing123123", "123d==")
	assert.NoError(t, err)
}

func TestLiveDynDnsCleanUp(t *testing.T) {
	if !dynLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 5)

	provider, err := NewDNSProviderCredentials(dynCustomerName, dynUsername, dynPassword, dynZoneName)
	assert.NoError(t, err)

	err = provider.CleanUp(dynZoneName, "", "123d==")
	assert.NoError(t, err)
}
