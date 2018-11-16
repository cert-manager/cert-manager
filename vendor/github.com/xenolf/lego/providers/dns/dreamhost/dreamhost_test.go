package dreamhost

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest("DREAMHOST_API_KEY").
	WithDomain("DREAMHOST_TEST_DOMAIN")

var (
	fakeAPIKey         = "asdf1234"
	fakeChallengeToken = "foobar"
	fakeKeyAuth        = "w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI"
)

func setupTest() (*DNSProvider, *http.ServeMux, func()) {
	handler := http.NewServeMux()
	server := httptest.NewServer(handler)

	config := NewDefaultConfig()
	config.APIKey = fakeAPIKey
	config.BaseURL = server.URL

	provider, err := NewDNSProviderConfig(config)
	if err != nil {
		panic(err)
	}

	return provider, handler, server.Close
}

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"DREAMHOST_API_KEY": "123",
			},
		},
		{
			desc: "missing API key",
			envVars: map[string]string{
				"DREAMHOST_API_KEY": "",
			},
			expected: "dreamhost: some credentials information are missing: DREAMHOST_API_KEY",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()
			envTest.ClearEnv()

			envTest.Apply(test.envVars)

			p, err := NewDNSProvider()

			if len(test.expected) == 0 {
				assert.NoError(t, err)
				assert.NotNil(t, p)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc     string
		apiKey   string
		expected string
	}{
		{
			desc:   "success",
			apiKey: "123",
		},
		{
			desc:     "missing credentials",
			expected: "dreamhost: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				assert.NoError(t, err)
				assert.NotNil(t, p)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestDNSProvider_Present(t *testing.T) {
	provider, mux, tearDown := setupTest()
	defer tearDown()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method, "method")

		q := r.URL.Query()
		assert.Equal(t, q.Get("key"), fakeAPIKey)
		assert.Equal(t, q.Get("cmd"), "dns-add_record")
		assert.Equal(t, q.Get("format"), "json")
		assert.Equal(t, q.Get("record"), "_acme-challenge.example.com")
		assert.Equal(t, q.Get("value"), fakeKeyAuth)
		assert.Equal(t, q.Get("comment"), "Managed+By+lego")

		_, err := fmt.Fprintf(w, `{"data":"record_added","result":"success"}`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	err := provider.Present("example.com", "", fakeChallengeToken)
	require.NoError(t, err)
}

func TestDNSProvider_PresentFailed(t *testing.T) {
	provider, mux, tearDown := setupTest()
	defer tearDown()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method, "method")

		_, err := fmt.Fprintf(w, `{"data":"record_already_exists_remove_first","result":"error"}`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	err := provider.Present("example.com", "", fakeChallengeToken)
	require.EqualError(t, err, "dreamhost: add TXT record failed: record_already_exists_remove_first")
}

func TestDNSProvider_Cleanup(t *testing.T) {
	provider, mux, tearDown := setupTest()
	defer tearDown()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method, "method")

		q := r.URL.Query()
		assert.Equal(t, q.Get("key"), fakeAPIKey, "key mismatch")
		assert.Equal(t, q.Get("cmd"), "dns-remove_record", "cmd mismatch")
		assert.Equal(t, q.Get("format"), "json")
		assert.Equal(t, q.Get("record"), "_acme-challenge.example.com")
		assert.Equal(t, q.Get("value"), fakeKeyAuth, "value mismatch")
		assert.Equal(t, q.Get("comment"), "Managed+By+lego")

		_, err := fmt.Fprintf(w, `{"data":"record_removed","result":"success"}`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	err := provider.CleanUp("example.com", "", fakeChallengeToken)
	require.NoError(t, err, "failed to remove TXT record")
}

func TestLivePresentAndCleanUp(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
