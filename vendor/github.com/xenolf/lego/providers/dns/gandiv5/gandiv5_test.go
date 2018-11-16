package gandiv5

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/log"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest("GANDIV5_API_KEY")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"GANDIV5_API_KEY": "123",
			},
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				"GANDIV5_API_KEY": "",
			},
			expected: "gandi: some credentials information are missing: GANDIV5_API_KEY",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()
			envTest.ClearEnv()

			envTest.Apply(test.envVars)

			p, err := NewDNSProvider()

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.inProgressFQDNs)
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
			expected: "gandiv5: no API Key given",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.inProgressFQDNs)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

// TestDNSProvider runs Present and CleanUp against a fake Gandi RPC
// Server, whose responses are predetermined for particular requests.
func TestDNSProvider(t *testing.T) {
	fakeKeyAuth := "XXXX"

	regexpToken, err := regexp.Compile(`"rrset_values":\[".+"\]`)
	require.NoError(t, err)

	// start fake RPC server
	handler := http.NewServeMux()
	handler.HandleFunc("/domains/example.com/records/_acme-challenge.abc.def/TXT", func(rw http.ResponseWriter, req *http.Request) {
		log.Infof("request: %s %s", req.Method, req.URL)

		if req.Header.Get(apiKeyHeader) == "" {
			http.Error(rw, `{"message": "missing API key"}`, http.StatusUnauthorized)
			return
		}

		if req.Method == http.MethodPost && req.Header.Get("Content-Type") != "application/json" {
			http.Error(rw, `{"message": "invalid content type"}`, http.StatusBadRequest)
			return
		}

		body, errS := ioutil.ReadAll(req.Body)
		if errS != nil {
			http.Error(rw, fmt.Sprintf(`{"message": "read body error: %v"}`, errS), http.StatusInternalServerError)
			return
		}

		body = regexpToken.ReplaceAllLiteral(body, []byte(`"rrset_values":["TOKEN"]`))

		responses, ok := serverResponses[req.Method]
		if !ok {
			http.Error(rw, fmt.Sprintf(`{"message": "Server response for request not found: %#q"}`, string(body)), http.StatusInternalServerError)
			return
		}

		resp := responses[string(body)]

		_, errS = rw.Write([]byte(resp))
		if errS != nil {
			http.Error(rw, fmt.Sprintf(`{"message": "failed to write response: %v"}`, errS), http.StatusInternalServerError)
			return
		}
	})
	handler.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		log.Infof("request: %s %s", req.Method, req.URL)
		http.Error(rw, fmt.Sprintf(`{"message": "URL doesn't match: %s"}`, req.URL), http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// define function to override findZoneByFqdn with
	fakeFindZoneByFqdn := func(fqdn string, nameserver []string) (string, error) {
		return "example.com.", nil
	}

	config := NewDefaultConfig()
	config.APIKey = "123412341234123412341234"
	config.BaseURL = server.URL

	provider, err := NewDNSProviderConfig(config)
	require.NoError(t, err)

	// override findZoneByFqdn function
	savedFindZoneByFqdn := findZoneByFqdn
	defer func() {
		findZoneByFqdn = savedFindZoneByFqdn
	}()
	findZoneByFqdn = fakeFindZoneByFqdn

	// run Present
	err = provider.Present("abc.def.example.com", "", fakeKeyAuth)
	require.NoError(t, err)

	// run CleanUp
	err = provider.CleanUp("abc.def.example.com", "", fakeKeyAuth)
	require.NoError(t, err)
}

// serverResponses is the JSON Request->Response map used by the
// fake JSON server.
var serverResponses = map[string]map[string]string{
	http.MethodGet: {
		``: `{"rrset_ttl":300,"rrset_values":[],"rrset_name":"_acme-challenge.abc.def","rrset_type":"TXT"}`,
	},
	http.MethodPut: {
		`{"rrset_ttl":300,"rrset_values":["TOKEN"]}`: `{"message": "Zone Record Created"}`,
	},
	http.MethodDelete: {
		``: ``,
	},
}
