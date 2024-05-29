// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package clouddns

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
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

func TestNewDNSProviderValid(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test (requires credentials)")
	}
	t.Setenv("GCE_PROJECT", "")
	_, err := NewDNSProviderCredentials(context.TODO(), "my-project", util.RecursiveNameservers, "")
	assert.NoError(t, err)
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test (requires credentials)")
	}
	t.Setenv("GCE_PROJECT", "my-project")
	_, err := NewDNSProviderEnvironment(context.TODO(), util.RecursiveNameservers, "")
	assert.NoError(t, err)
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	t.Setenv("GCE_PROJECT", "")
	_, err := NewDNSProviderEnvironment(context.TODO(), util.RecursiveNameservers, "")
	assert.EqualError(t, err, "Google Cloud project name missing")
}

func TestLiveGoogleCloudPresent(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(context.TODO(), gcloudProject, util.RecursiveNameservers, "")
	assert.NoError(t, err)

	err = provider.Present(context.TODO(), gcloudDomain, "_acme-challenge."+gcloudDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestLiveGoogleCloudPresentMultiple(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(context.TODO(), gcloudProject, util.RecursiveNameservers, "")
	assert.NoError(t, err)

	// Check that we're able to create multiple entries
	err = provider.Present(context.TODO(), gcloudDomain, "_acme-challenge."+gcloudDomain+".", "123d==")
	assert.NoError(t, err)
	err = provider.Present(context.TODO(), gcloudDomain, "_acme-challenge."+gcloudDomain+".", "1123d==")
	assert.NoError(t, err)
}

func TestLiveGoogleCloudCleanUp(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 1)

	provider, err := NewDNSProviderCredentials(context.TODO(), gcloudProject, util.RecursiveNameservers, "")
	assert.NoError(t, err)

	err = provider.CleanUp(context.TODO(), gcloudDomain, "_acme-challenge."+gcloudDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestDNSProvider_getHostedZone(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	testProvider, err := NewDNSProviderCredentials(context.TODO(), "my-project", util.RecursiveNameservers, "test-zone")
	assert.NoError(t, err)

	type args struct {
		domain string
	}
	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		provider *DNSProvider
	}{
		{
			name:     "test given hosted zone name",
			provider: testProvider,
			want:     "test-zone",
			wantErr:  false,
			args:     args{domain: "example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.provider
			got, err := c.getHostedZone(context.TODO(), tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("getHostedZone() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getHostedZone() got = %v, want %v", got, tt.want)
			}
		})
	}
}
