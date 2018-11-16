package rackspace

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"RACKSPACE_USER",
	"RACKSPACE_API_KEY").
	WithDomain("RACKSPACE_DOMAIN")

func TestNewDNSProviderConfig(t *testing.T) {
	config, tearDown := setupTest()
	defer tearDown()

	provider, err := NewDNSProviderConfig(config)
	require.NoError(t, err)
	assert.NotNil(t, provider.config)

	assert.Equal(t, provider.token, "testToken", "The token should match")
}

func TestNewDNSProviderConfig_MissingCredErr(t *testing.T) {
	_, err := NewDNSProviderConfig(NewDefaultConfig())
	assert.EqualError(t, err, "rackspace: credentials missing")
}

func TestDNSProvider_Present(t *testing.T) {
	config, tearDown := setupTest()
	defer tearDown()

	provider, err := NewDNSProviderConfig(config)

	if assert.NoError(t, err) {
		err = provider.Present("example.com", "token", "keyAuth")
		require.NoError(t, err)
	}
}

func TestDNSProvider_CleanUp(t *testing.T) {
	config, tearDown := setupTest()
	defer tearDown()

	provider, err := NewDNSProviderConfig(config)

	if assert.NoError(t, err) {
		err = provider.CleanUp("example.com", "token", "keyAuth")
		require.NoError(t, err)
	}
}

func TestLiveNewDNSProvider_ValidEnv(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	assert.Contains(t, provider.cloudDNSEndpoint, "https://dns.api.rackspacecloud.com/v1.0/", "The endpoint URL should contain the base")
}

func TestLivePresent(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "", "112233445566==")
	require.NoError(t, err)
}

func TestLiveCleanUp(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	time.Sleep(15 * time.Second)

	err = provider.CleanUp(envTest.GetDomain(), "", "112233445566==")
	require.NoError(t, err)
}

func setupTest() (*Config, func()) {
	apiURL, tearDown := startTestServers()

	config := NewDefaultConfig()
	config.APIUser = "testUser"
	config.APIKey = "testKey"
	config.BaseURL = apiURL

	return config, tearDown
}

func startTestServers() (string, func()) {
	dnsAPI := httptest.NewServer(dnsHandler())
	identityAPI := httptest.NewServer(identityHandler(dnsAPI.URL + "/123456"))

	return identityAPI.URL + "/", func() {
		identityAPI.Close()
		dnsAPI.Close()
	}
}

func identityHandler(dnsEndpoint string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp, found := jsonMap[string(reqBody)]
		if !found {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp = strings.Replace(resp, "https://dns.api.rackspacecloud.com/v1.0/123456", dnsEndpoint, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, resp)
	})
}

func dnsHandler() *http.ServeMux {
	mux := http.NewServeMux()

	// Used by `getHostedZoneID()` finding `zoneID` "?name=example.com"
	mux.HandleFunc("/123456/domains", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") == "example.com" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, jsonMap["zoneDetails"])
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})

	mux.HandleFunc("/123456/domains/112233/records", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		// Used by `Present()` creating the TXT record
		case http.MethodPost:
			reqBody, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp, found := jsonMap[string(reqBody)]
			if !found {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			fmt.Fprintf(w, resp)
			// Used by `findTxtRecord()` finding `record.ID` "?type=TXT&name=_acme-challenge.example.com"
		case http.MethodGet:
			if r.URL.Query().Get("type") == "TXT" && r.URL.Query().Get("name") == "_acme-challenge.example.com" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, jsonMap["recordDetails"])
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
			// Used by `CleanUp()` deleting the TXT record "?id=445566"
		case http.MethodDelete:
			if r.URL.Query().Get("id") == "TXT-654321" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, jsonMap["recordDelete"])
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Printf("Not Found for Request: (%+v)\n\n", r)
	})

	return mux
}

var jsonMap = map[string]string{
	`{"auth":{"RAX-KSKEY:apiKeyCredentials":{"username":"testUser","apiKey":"testKey"}}}`: `{"access":{"token":{"id":"testToken","expires":"1970-01-01T00:00:00.000Z","tenant":{"id":"123456","name":"123456"},"RAX-AUTH:authenticatedBy":["APIKEY"]},"serviceCatalog":[{"type":"rax:dns","endpoints":[{"publicURL":"https://dns.api.rackspacecloud.com/v1.0/123456","tenantId":"123456"}],"name":"cloudDNS"}],"user":{"id":"fakeUseID","name":"testUser"}}}`,
	"zoneDetails": `{"domains":[{"name":"example.com","id":112233,"emailAddress":"hostmaster@example.com","updated":"1970-01-01T00:00:00.000+0000","created":"1970-01-01T00:00:00.000+0000"}],"totalEntries":1}`,
	`{"records":[{"name":"_acme-challenge.example.com","type":"TXT","data":"pW9ZKG0xz_PCriK-nCMOjADy9eJcgGWIzkkj2fN4uZM","ttl":300}]}`: `{"request":"{\"records\":[{\"name\":\"_acme-challenge.example.com\",\"type\":\"TXT\",\"data\":\"pW9ZKG0xz_PCriK-nCMOjADy9eJcgGWIzkkj2fN4uZM\",\"ttl\":300}]}","status":"RUNNING","verb":"POST","jobId":"00000000-0000-0000-0000-0000000000","callbackUrl":"https://dns.api.rackspacecloud.com/v1.0/123456/status/00000000-0000-0000-0000-0000000000","requestUrl":"https://dns.api.rackspacecloud.com/v1.0/123456/domains/112233/records"}`,
	"recordDetails": `{"records":[{"name":"_acme-challenge.example.com","id":"TXT-654321","type":"TXT","data":"pW9ZKG0xz_PCriK-nCMOjADy9eJcgGWIzkkj2fN4uZM","ttl":300,"updated":"1970-01-01T00:00:00.000+0000","created":"1970-01-01T00:00:00.000+0000"}]}`,
	"recordDelete":  `{"status":"RUNNING","verb":"DELETE","jobId":"00000000-0000-0000-0000-0000000000","callbackUrl":"https://dns.api.rackspacecloud.com/v1.0/123456/status/00000000-0000-0000-0000-0000000000","requestUrl":"https://dns.api.rackspacecloud.com/v1.0/123456/domains/112233/recordsid=TXT-654321"}`,
}
