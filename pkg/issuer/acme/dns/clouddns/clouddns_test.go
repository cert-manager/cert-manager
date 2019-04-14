// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package clouddns

import (
	"os"
	"testing"

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
	_, err := NewDNSProviderAmbientCredentials("my-project")
	assert.NoError(t, err)
	restoreGCloudEnv()
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	_, err := NewDNSProviderAmbientCredentials("")
	assert.EqualError(t, err, "Google Cloud project name missing")
	restoreGCloudEnv()
}
