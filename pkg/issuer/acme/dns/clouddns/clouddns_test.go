// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package clouddns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

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
	_, err := NewDNSProviderCredentials(t.Context(), "my-project", util.RecursiveNameservers, "")
	assert.NoError(t, err)
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test (requires credentials)")
	}
	t.Setenv("GCE_PROJECT", "my-project")
	_, err := NewDNSProviderEnvironment(t.Context(), util.RecursiveNameservers, "")
	assert.NoError(t, err)
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	t.Setenv("GCE_PROJECT", "")
	_, err := NewDNSProviderEnvironment(t.Context(), util.RecursiveNameservers, "")
	assert.EqualError(t, err, "Google Cloud project name missing")
}

func TestLiveGoogleCloudPresent(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(t.Context(), gcloudProject, util.RecursiveNameservers, "")
	assert.NoError(t, err)

	err = provider.Present(t.Context(), gcloudDomain, "_acme-challenge."+gcloudDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestLiveGoogleCloudPresentMultiple(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(t.Context(), gcloudProject, util.RecursiveNameservers, "")
	assert.NoError(t, err)

	// Check that we're able to create multiple entries
	err = provider.Present(t.Context(), gcloudDomain, "_acme-challenge."+gcloudDomain+".", "123d==")
	assert.NoError(t, err)
	err = provider.Present(t.Context(), gcloudDomain, "_acme-challenge."+gcloudDomain+".", "1123d==")
	assert.NoError(t, err)
}

func TestLiveGoogleCloudCleanUp(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 1)

	provider, err := NewDNSProviderCredentials(t.Context(), gcloudProject, util.RecursiveNameservers, "")
	assert.NoError(t, err)

	err = provider.CleanUp(t.Context(), gcloudDomain, "_acme-challenge."+gcloudDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestNewDNSProviderFromOptions(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T)
		options []DNSProviderOption
		wantErr string
	}{
		{
			name: "valid with ambient credentials",
			setup: func(t *testing.T) {
				if !gcloudLiveTest {
					t.Skip("skipping live test (requires credentials)")
				}
			},
			options: []DNSProviderOption{
				Project("my-project"),
				Ambient(true),
				Nameservers(util.RecursiveNameservers),
				Resolver(util.NewCachingResolver()),
			},
		},
		{
			name: "empty credentials without ambient",
			options: []DNSProviderOption{
				Project("my-project"),
				Nameservers(util.RecursiveNameservers),
				Resolver(util.NewCachingResolver()),
			},
			wantErr: "unable to construct clouddns provider: empty credentials",
		},
		{
			name: "missing project",
			options: []DNSProviderOption{
				Nameservers(util.RecursiveNameservers),
				Resolver(util.NewCachingResolver()),
			},
			wantErr: "Google Cloud project name missing",
		},
		{
			name: "missing nameservers",
			options: []DNSProviderOption{
				Project("my-project"),
				Resolver(util.NewCachingResolver()),
			},
			wantErr: "nameservers are required",
		},
		{
			name: "missing resolver",
			options: []DNSProviderOption{
				Project("my-project"),
				Nameservers(util.RecursiveNameservers),
			},
			wantErr: "resolver is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}
			_, err := NewDNSProviderFromOptions(t.Context(), tt.options...)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestDNSProvider_getHostedZone(t *testing.T) {
	if !gcloudLiveTest {
		t.Skip("skipping live test")
	}

	testProvider, err := NewDNSProviderFromOptions(t.Context(),
		Project("my-project"),
		Ambient(true),
		HostedZoneName("test-zone"),
		Nameservers(util.RecursiveNameservers),
		Resolver(util.NewCachingResolver()))

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
			got, err := c.getHostedZone(t.Context(), tt.args.domain)
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

type fakeResolver struct {
	util.Resolver
	zone string
}

func (f fakeResolver) FindZoneByFQDN(ctx context.Context, fqdn string, nameservers []string) (string, error) {
	return f.zone, nil
}

func newFakeProvider(t *testing.T, handler http.HandlerFunc) *DNSProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	svc, err := dns.NewService(t.Context(),
		option.WithEndpoint(srv.URL),
		option.WithoutAuthentication(),
	)
	require.NoError(t, err)

	return &DNSProvider{
		project:          "my-project",
		client:           svc,
		dns01Nameservers: []string{"127.0.0.1:53"},
		resolver:         fakeResolver{zone: "example.com."},
		log:              logr.Discard(),
	}
}

func TestCleanUpNoMatchingManagedZone(t *testing.T) {
	var requests []string
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"managedZones": []}`))
	})

	// Present fails because there is no managed zone.
	err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "123d==")
	assert.ErrorContains(t, err, "no matching GoogleCloud domain found for domain example.com.")

	// CleanUp must succeed, otherwise the Challenge can never be removed.
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.", "123d==")
	assert.NoError(t, err)

	assert.Len(t, requests, 2, "Present and CleanUp should each list managed zones")
	for _, req := range requests {
		assert.NotContains(t, req, "POST", "no changes should be made when there is no managed zone")
	}
}

func TestCleanUpManagedZoneListError(t *testing.T) {
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.", "123d==")
	assert.ErrorContains(t, err, "GoogleCloud API call failed")
}
