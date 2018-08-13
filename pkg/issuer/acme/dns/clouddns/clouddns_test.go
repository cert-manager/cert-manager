/*
Copyright 2018 The Jetstack cert-manager contributors.

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

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package clouddns

import (
	"os"
	"testing"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"

	"github.com/stretchr/testify/assert"
)

var (
	gcloudLiveTest bool
	gcloudProject  string
	gcloudDomain   string
)

func init() {
	gcloudProject = os.Getenv("GCE_PROJECT")
	gcloudDomain = os.Getenv("GCE_DOMAIN")
	_, err := google.DefaultClient(context.Background(), dns.NdevClouddnsReadwriteScope)
	if err == nil && len(gcloudProject) > 0 && len(gcloudDomain) > 0 {
		gcloudLiveTest = true
	}
}

func restoreGCloudEnv() {
	os.Setenv("GCE_PROJECT", gcloudProject)
}

func TestNewDNSProviderValid(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test (requires credentials)")
	}
	os.Setenv("GCE_PROJECT", "")
	_, err := NewDNSProviderCredentials("my-project")
	assert.NoError(t, err)
	restoreGCloudEnv()
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test (requires credentials)")
	}
	os.Setenv("GCE_PROJECT", "my-project")
	_, err := NewDNSProvider()
	assert.NoError(t, err)
	restoreGCloudEnv()
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	os.Setenv("GCE_PROJECT", "")
	_, err := NewDNSProvider()
	assert.EqualError(t, err, "Google Cloud project name missing")
	restoreGCloudEnv()
}

func TestLiveGoogleCloudPresent(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(gcloudProject)
	assert.NoError(t, err)

	err = provider.Present(gcloudDomain, "", "123d==")
	assert.NoError(t, err)
}

func TestLiveGoogleCloudPresentMultiple(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(gcloudProject)
	assert.NoError(t, err)

	// Check that we're able to create multiple entries
	err = provider.Present(gcloudDomain, "1", "123d==")
	err = provider.Present(gcloudDomain, "2", "123d==")
	assert.NoError(t, err)
}

func TestLiveGoogleCloudCleanUp(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 1)

	provider, err := NewDNSProviderCredentials(gcloudProject)
	assert.NoError(t, err)

	err = provider.CleanUp(gcloudDomain, "", "123d==")
	assert.NoError(t, err)
}
