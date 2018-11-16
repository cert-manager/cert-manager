package cloudxns

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func handlerMock(method string, response *apiResponse, data interface{}) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != method {
			content, err := json.Marshal(apiResponse{
				Code:    999, // random code only for the test
				Message: fmt.Sprintf("invalid method: got %s want %s", req.Method, method),
			})
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}

			http.Error(rw, string(content), http.StatusBadRequest)
			return
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		response.Data = jsonData

		content, err := json.Marshal(response)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = rw.Write(content)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func TestClientGetDomainInformation(t *testing.T) {
	type result struct {
		domain *Data
		error  bool
	}

	testCases := []struct {
		desc     string
		fqdn     string
		response *apiResponse
		data     []Data
		expected result
	}{
		{
			desc: "domain found",
			fqdn: "_acme-challenge.foo.com.",
			response: &apiResponse{
				Code: 1,
			},
			data: []Data{
				{
					ID:     "1",
					Domain: "bar.com.",
				},
				{
					ID:     "2",
					Domain: "foo.com.",
				},
			},
			expected: result{domain: &Data{
				ID:     "2",
				Domain: "foo.com.",
			}},
		},
		{
			desc: "domains not found",
			fqdn: "_acme-challenge.huu.com.",
			response: &apiResponse{
				Code: 1,
			},
			data: []Data{
				{
					ID:     "5",
					Domain: "bar.com.",
				},
				{
					ID:     "6",
					Domain: "foo.com.",
				},
			},
			expected: result{error: true},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {

			server := httptest.NewServer(handlerMock(http.MethodGet, test.response, test.data))

			client, _ := NewClient("myKey", "mySecret")
			client.BaseURL = server.URL + "/"

			domain, err := client.GetDomainInformation(test.fqdn)

			if test.expected.error {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expected.domain, domain)
			}
		})
	}
}

func TestClientFindTxtRecord(t *testing.T) {
	type result struct {
		txtRecord *TXTRecord
		error     bool
	}

	testCases := []struct {
		desc       string
		fqdn       string
		zoneID     string
		txtRecords []TXTRecord
		response   *apiResponse
		expected   result
	}{
		{
			desc:   "record found",
			fqdn:   "_acme-challenge.foo.com.",
			zoneID: "test-zone",
			txtRecords: []TXTRecord{
				{
					ID:       1,
					RecordID: "Record-A",
					Host:     "_acme-challenge.foo.com",
					Value:    "txtTXTtxtTXTtxtTXTtxtTXT",
					Type:     "TXT",
					LineID:   6,
					TTL:      30,
				},
				{
					ID:       2,
					RecordID: "Record-B",
					Host:     "_acme-challenge.bar.com",
					Value:    "TXTtxtTXTtxtTXTtxtTXTtxt",
					Type:     "TXT",
					LineID:   6,
					TTL:      30,
				},
			},
			response: &apiResponse{
				Code: 1,
			},
			expected: result{
				txtRecord: &TXTRecord{
					ID:       1,
					RecordID: "Record-A",
					Host:     "_acme-challenge.foo.com",
					Value:    "txtTXTtxtTXTtxtTXTtxtTXT",
					Type:     "TXT",
					LineID:   6,
					TTL:      30,
				},
			},
		},
		{
			desc:   "record not found",
			fqdn:   "_acme-challenge.huu.com.",
			zoneID: "test-zone",
			txtRecords: []TXTRecord{
				{
					ID:       1,
					RecordID: "Record-A",
					Host:     "_acme-challenge.foo.com",
					Value:    "txtTXTtxtTXTtxtTXTtxtTXT",
					Type:     "TXT",
					LineID:   6,
					TTL:      30,
				},
				{
					ID:       2,
					RecordID: "Record-B",
					Host:     "_acme-challenge.bar.com",
					Value:    "TXTtxtTXTtxtTXTtxtTXTtxt",
					Type:     "TXT",
					LineID:   6,
					TTL:      30,
				},
			},
			response: &apiResponse{
				Code: 1,
			},
			expected: result{error: true},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {

			server := httptest.NewServer(handlerMock(http.MethodGet, test.response, test.txtRecords))

			client, _ := NewClient("myKey", "mySecret")
			client.BaseURL = server.URL + "/"

			txtRecord, err := client.FindTxtRecord(test.zoneID, test.fqdn)

			if test.expected.error {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expected.txtRecord, txtRecord)
			}
		})
	}
}

func TestClientAddTxtRecord(t *testing.T) {
	testCases := []struct {
		desc     string
		domain   *Data
		fqdn     string
		value    string
		ttl      int
		expected string
	}{
		{
			desc: "sub-domain",
			domain: &Data{
				ID:     "1",
				Domain: "bar.com.",
			},
			fqdn:     "_acme-challenge.foo.bar.com.",
			value:    "txtTXTtxtTXTtxtTXTtxtTXT",
			ttl:      30,
			expected: `{"domain_id":1,"host":"_acme-challenge.foo","value":"txtTXTtxtTXTtxtTXTtxtTXT","type":"TXT","line_id":"1","ttl":"30"}`,
		},
		{
			desc: "main domain",
			domain: &Data{
				ID:     "2",
				Domain: "bar.com.",
			},
			fqdn:     "_acme-challenge.bar.com.",
			value:    "TXTtxtTXTtxtTXTtxtTXTtxt",
			ttl:      30,
			expected: `{"domain_id":2,"host":"_acme-challenge","value":"TXTtxtTXTtxtTXTtxtTXTtxt","type":"TXT","line_id":"1","ttl":"30"}`,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			response := &apiResponse{
				Code: 1,
			}

			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				assert.NotNil(t, req.Body)
				content, err := ioutil.ReadAll(req.Body)
				require.NoError(t, err)

				assert.Equal(t, test.expected, string(content))

				handlerMock(http.MethodPost, response, nil).ServeHTTP(rw, req)
			}))

			client, _ := NewClient("myKey", "mySecret")
			client.BaseURL = server.URL + "/"

			err := client.AddTxtRecord(test.domain, test.fqdn, test.value, test.ttl)
			require.NoError(t, err)
		})
	}
}
