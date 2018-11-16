package httpreq

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest("HTTPREQ_ENDPOINT", "HTTPREQ_MODE", "HTTPREQ_USERNAME", "HTTPREQ_PASSWORD")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"HTTPREQ_ENDPOINT": "http://localhost:8090",
			},
		},
		{
			desc: "invalid URL",
			envVars: map[string]string{
				"HTTPREQ_ENDPOINT": ":",
			},
			expected: "httpreq: parse :: missing protocol scheme",
		},
		{
			desc: "missing endpoint",
			envVars: map[string]string{
				"HTTPREQ_ENDPOINT": "",
			},
			expected: "httpreq: some credentials information are missing: HTTPREQ_ENDPOINT",
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
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc     string
		endpoint *url.URL
		expected string
	}{
		{
			desc:     "success",
			endpoint: mustParse("http://localhost:8090"),
		},
		{
			desc:     "missing endpoint",
			expected: "httpreq: the endpoint is missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.Endpoint = test.endpoint

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProvider_Present(t *testing.T) {
	envTest.RestoreEnv()

	testCases := []struct {
		desc          string
		mode          string
		username      string
		password      string
		handler       http.HandlerFunc
		expectedError string
	}{
		{
			desc:    "success",
			handler: successHandler,
		},
		{
			desc:          "error",
			handler:       http.NotFound,
			expectedError: "httpreq: 404: request failed: 404 page not found\n",
		},
		{
			desc:    "success raw mode",
			mode:    "RAW",
			handler: successRawModeHandler,
		},
		{
			desc:          "error raw mode",
			mode:          "RAW",
			handler:       http.NotFound,
			expectedError: "httpreq: 404: request failed: 404 page not found\n",
		},
		{
			desc:     "basic auth",
			username: "bar",
			password: "foo",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				username, password, ok := req.BasicAuth()
				if username != "bar" || password != "foo" || !ok {
					rw.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, "Please enter your username and password."))
					http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}

				fmt.Fprint(rw, "lego")
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			mux := http.NewServeMux()
			mux.HandleFunc("/present", test.handler)
			server := httptest.NewServer(mux)

			config := NewDefaultConfig()
			config.Endpoint = mustParse(server.URL)
			config.Mode = test.mode
			config.Username = test.username
			config.Password = test.password

			p, err := NewDNSProviderConfig(config)
			require.NoError(t, err)

			err = p.Present("domain", "token", "key")
			if test.expectedError == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.expectedError)
			}
		})
	}
}

func TestNewDNSProvider_Cleanup(t *testing.T) {
	envTest.RestoreEnv()

	testCases := []struct {
		desc          string
		mode          string
		username      string
		password      string
		handler       http.HandlerFunc
		expectedError string
	}{
		{
			desc:    "success",
			handler: successHandler,
		},
		{
			desc:          "error",
			handler:       http.NotFound,
			expectedError: "httpreq: 404: request failed: 404 page not found\n",
		},
		{
			desc:    "success raw mode",
			mode:    "RAW",
			handler: successRawModeHandler,
		},
		{
			desc:          "error raw mode",
			mode:          "RAW",
			handler:       http.NotFound,
			expectedError: "httpreq: 404: request failed: 404 page not found\n",
		},
		{
			desc:     "basic auth",
			username: "bar",
			password: "foo",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				username, password, ok := req.BasicAuth()
				if username != "bar" || password != "foo" || !ok {
					rw.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, "Please enter your username and password."))
					http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				fmt.Fprint(rw, "lego")
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			mux := http.NewServeMux()
			mux.HandleFunc("/cleanup", test.handler)
			server := httptest.NewServer(mux)

			config := NewDefaultConfig()
			config.Endpoint = mustParse(server.URL)
			config.Mode = test.mode
			config.Username = test.username
			config.Password = test.password

			p, err := NewDNSProviderConfig(config)
			require.NoError(t, err)

			err = p.CleanUp("domain", "token", "key")
			if test.expectedError == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.expectedError)
			}
		})
	}
}

func successHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	msg := &message{}
	err := json.NewDecoder(req.Body).Decode(msg)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprint(rw, "lego")
}

func successRawModeHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	msg := &messageRaw{}
	err := json.NewDecoder(req.Body).Decode(msg)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprint(rw, "lego")
}

func mustParse(rawURL string) *url.URL {
	uri, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return uri
}
