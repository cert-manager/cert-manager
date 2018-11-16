package conoha

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func setupClientTest() (*http.ServeMux, *Client, func()) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	client := &Client{
		token:      "secret",
		endpoint:   server.URL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	return mux, client, server.Close
}

func TestClient_GetDomainID(t *testing.T) {
	type expected struct {
		domainID string
		error    bool
	}

	testCases := []struct {
		desc       string
		domainName string
		handler    http.HandlerFunc
		expected   expected
	}{
		{
			desc:       "success",
			domainName: "domain1.com.",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet {
					http.Error(rw, fmt.Sprintf("%s: %s", http.StatusText(http.StatusMethodNotAllowed), req.Method), http.StatusMethodNotAllowed)
					return
				}

				content := `
{
    "domains":[
      {
        "id": "09494b72-b65b-4297-9efb-187f65a0553e",
        "name": "domain1.com.",
        "ttl": 3600,
        "serial": 1351800668,
        "email": "nsadmin@example.org",
        "gslb": 0,
        "created_at": "2012-11-01T20:11:08.000000",
        "updated_at": null,
        "description": "memo"
      },
      {
        "id": "cf661142-e577-40b5-b3eb-75795cdc0cd7",
        "name": "domain2.com.",
        "ttl": 7200,
        "serial": 1351800670,
        "email": "nsadmin2@example.org",
        "gslb": 1,
        "created_at": "2012-11-01T20:11:08.000000",
        "updated_at": "2012-12-01T20:11:08.000000",
        "description": "memomemo"
      }
    ]
}
`
				_, err := fmt.Fprint(rw, content)
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
					return
				}
			},
			expected: expected{domainID: "09494b72-b65b-4297-9efb-187f65a0553e"},
		},
		{
			desc:       "non existing domain",
			domainName: "domain1.com.",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet {
					http.Error(rw, fmt.Sprintf("%s: %s", http.StatusText(http.StatusMethodNotAllowed), req.Method), http.StatusMethodNotAllowed)
					return
				}

				_, err := fmt.Fprint(rw, "{}")
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
					return
				}
			},
			expected: expected{error: true},
		},
		{
			desc:       "marshaling error",
			domainName: "domain1.com.",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet {
					http.Error(rw, fmt.Sprintf("%s: %s", http.StatusText(http.StatusMethodNotAllowed), req.Method), http.StatusMethodNotAllowed)
					return
				}

				_, err := fmt.Fprint(rw, "[]")
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
					return
				}
			},
			expected: expected{error: true},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			mux, client, tearDown := setupClientTest()
			defer tearDown()

			mux.Handle("/v1/domains", test.handler)

			domainID, err := client.GetDomainID(test.domainName)

			if test.expected.error {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expected.domainID, domainID)
			}
		})
	}

}

func TestClient_CreateRecord(t *testing.T) {
	testCases := []struct {
		desc        string
		handler     http.HandlerFunc
		expectError bool
	}{
		{
			desc: "success",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodPost {
					http.Error(rw, fmt.Sprintf("%s: %s", http.StatusText(http.StatusMethodNotAllowed), req.Method), http.StatusMethodNotAllowed)
					return
				}

				raw, err := ioutil.ReadAll(req.Body)
				if err != nil {
					http.Error(rw, err.Error(), http.StatusBadRequest)
					return
				}
				defer req.Body.Close()

				if string(raw) != `{"name":"lego.com.","type":"TXT","data":"txtTXTtxt","ttl":300}` {
					http.Error(rw, fmt.Sprintf("invalid request body: %s", string(raw)), http.StatusBadRequest)
					return
				}
			},
		},
		{
			desc: "bad request",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodPost {
					http.Error(rw, fmt.Sprintf("%s: %s", http.StatusText(http.StatusMethodNotAllowed), req.Method), http.StatusMethodNotAllowed)
					return
				}

				http.Error(rw, "OOPS", http.StatusBadRequest)
			},
			expectError: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			mux, client, tearDown := setupClientTest()
			defer tearDown()

			mux.Handle("/v1/domains/lego/records", test.handler)

			domainID := "lego"

			record := Record{
				Name: "lego.com.",
				Type: "TXT",
				Data: "txtTXTtxt",
				TTL:  300,
			}

			err := client.CreateRecord(domainID, record)

			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

		})
	}

}
