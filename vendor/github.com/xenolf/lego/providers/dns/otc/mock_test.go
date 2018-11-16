package otc

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var fakeOTCToken = "62244bc21da68d03ebac94e6636ff01f"

// DNSServerMock mock
type DNSServerMock struct {
	t      *testing.T
	server *httptest.Server
	Mux    *http.ServeMux
}

// NewDNSServerMock create a new DNSServerMock
func NewDNSServerMock(t *testing.T) *DNSServerMock {
	mux := http.NewServeMux()

	return &DNSServerMock{
		t:      t,
		server: httptest.NewServer(mux),
		Mux:    mux,
	}
}

func (m *DNSServerMock) GetServerURL() string {
	return m.server.URL
}

// ShutdownServer creates the mock server
func (m *DNSServerMock) ShutdownServer() {
	m.server.Close()
}

// HandleAuthSuccessfully Handle auth successfully
func (m *DNSServerMock) HandleAuthSuccessfully() {
	m.Mux.HandleFunc("/v3/auth/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Subject-Token", fakeOTCToken)

		fmt.Fprintf(w, `{
		  "token": {
		    "catalog": [
		      {
			"type": "dns",
			"id": "56cd81db1f8445d98652479afe07c5ba",
			"name": "",
			"endpoints": [
			  {
			    "url": "%s",
			    "region": "eu-de",
			    "region_id": "eu-de",
			    "interface": "public",
			    "id": "0047a06690484d86afe04877074efddf"
			  }
			]
		      }
		    ]
		  }}`, m.server.URL)
	})
}

// HandleListZonesSuccessfully Handle list zones successfully
func (m *DNSServerMock) HandleListZonesSuccessfully() {
	m.Mux.HandleFunc("/v2/zones", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(m.t, r.Method, http.MethodGet)
		assert.Equal(m.t, r.URL.Path, "/v2/zones")
		assert.Equal(m.t, r.URL.RawQuery, "name=example.com.")
		assert.Equal(m.t, r.Header.Get("Content-Type"), "application/json")

		fmt.Fprintf(w, `{
		  "zones":[{
		    "id":"123123"
		  }]}
		`)

	})
}

// HandleListZonesEmpty Handle list zones empty
func (m *DNSServerMock) HandleListZonesEmpty() {
	m.Mux.HandleFunc("/v2/zones", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(m.t, r.Method, http.MethodGet)
		assert.Equal(m.t, r.URL.Path, "/v2/zones")
		assert.Equal(m.t, r.URL.RawQuery, "name=example.com.")
		assert.Equal(m.t, r.Header.Get("Content-Type"), "application/json")

		fmt.Fprintf(w, `{
		  "zones":[
		  ]}
		`)
	})
}

// HandleDeleteRecordsetsSuccessfully Handle delete recordsets successfully
func (m *DNSServerMock) HandleDeleteRecordsetsSuccessfully() {
	m.Mux.HandleFunc("/v2/zones/123123/recordsets/321321", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(m.t, r.Method, http.MethodDelete)
		assert.Equal(m.t, r.URL.Path, "/v2/zones/123123/recordsets/321321")
		assert.Equal(m.t, r.Header.Get("Content-Type"), "application/json")

		fmt.Fprintf(w, `{
		  "zones":[{
		    "id":"123123"
		  }]}
		`)
	})
}

// HandleListRecordsetsEmpty Handle list recordsets empty
func (m *DNSServerMock) HandleListRecordsetsEmpty() {
	m.Mux.HandleFunc("/v2/zones/123123/recordsets", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(m.t, r.URL.Path, "/v2/zones/123123/recordsets")
		assert.Equal(m.t, r.URL.RawQuery, "type=TXT&name=_acme-challenge.example.com.")

		fmt.Fprintf(w, `{
		  "recordsets":[
		  ]}
		`)
	})
}

// HandleListRecordsetsSuccessfully Handle list recordsets successfully
func (m *DNSServerMock) HandleListRecordsetsSuccessfully() {
	m.Mux.HandleFunc("/v2/zones/123123/recordsets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			assert.Equal(m.t, r.URL.Path, "/v2/zones/123123/recordsets")
			assert.Equal(m.t, r.URL.RawQuery, "type=TXT&name=_acme-challenge.example.com.")
			assert.Equal(m.t, r.Header.Get("Content-Type"), "application/json")

			fmt.Fprintf(w, `{
			  "recordsets":[{
			    "id":"321321"
			  }]}
			`)
			return
		}

		if r.Method == http.MethodPost {
			assert.Equal(m.t, r.Header.Get("Content-Type"), "application/json")

			body, err := ioutil.ReadAll(r.Body)
			assert.Nil(m.t, err)
			exceptedString := "{\"name\":\"_acme-challenge.example.com.\",\"description\":\"Added TXT record for ACME dns-01 challenge using lego client\",\"type\":\"TXT\",\"ttl\":300,\"records\":[\"\\\"w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI\\\"\"]}"
			assert.Equal(m.t, string(body), exceptedString)
			fmt.Fprintf(w, `{
			  "recordsets":[{
                            "id":"321321"
			  }]}
			`)
			return
		}

		http.Error(w, fmt.Sprintf("Expected method to be 'GET' or 'POST' but got '%s'", r.Method), http.StatusBadRequest)
	})
}
