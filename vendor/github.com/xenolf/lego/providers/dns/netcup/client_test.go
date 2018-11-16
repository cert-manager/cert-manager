package netcup

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/acme"
)

func setupClientTest() (*Client, *http.ServeMux, func()) {
	handler := http.NewServeMux()
	server := httptest.NewServer(handler)

	client, err := NewClient("a", "b", "c")
	if err != nil {
		panic(err)
	}
	client.BaseURL = server.URL

	return client, handler, server.Close
}

func TestClient_Login(t *testing.T) {
	client, mux, tearDown := setupClientTest()
	defer tearDown()

	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		raw, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}

		if string(raw) != `{"action":"login","param":{"customernumber":"a","apikey":"b","apipassword":"c"}}` {
			http.Error(rw, fmt.Sprintf("invalid request body: %s", string(raw)), http.StatusBadRequest)
		}

		response := `
		{
		    "serverrequestid": "srv-request-id",
		    "clientrequestid": "",
		    "action": "login",
		    "status": "success",
		    "statuscode": 2000,
		    "shortmessage": "Login successful",
		    "longmessage": "Session has been created successful.",
		    "responsedata": {
		        "apisessionid": "api-session-id"
		    }
		}
		`
		_, err = rw.Write([]byte(response))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	})

	sessionID, err := client.Login()
	require.NoError(t, err)

	assert.Equal(t, "api-session-id", sessionID)
}

func TestClient_Login_errors(t *testing.T) {
	testCases := []struct {
		desc    string
		handler func(rw http.ResponseWriter, req *http.Request)
	}{
		{
			desc: "HTTP error",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				http.Error(rw, "error message", http.StatusInternalServerError)
			},
		},
		{
			desc: "API error",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				response := `
					{
						"serverrequestid":"YxTr4EzdbJ101T211zR4yzUEMVE",
						"clientrequestid":"",
						"action":"login",
						"status":"error",
						"statuscode":4013,
						"shortmessage":"Validation Error.",
						"longmessage":"Message is empty.",
						"responsedata":""
					}`
				_, err := rw.Write([]byte(response))
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
				}
			},
		},
		{
			desc: "responsedata marshaling error",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				response := `
							{
								"serverrequestid": "srv-request-id",
								"clientrequestid": "",
								"action": "login",
								"status": "success",
								"statuscode": 2000,
								"shortmessage": "Login successful",
								"longmessage": "Session has been created successful.",
								"responsedata": ""
							}`
				_, err := rw.Write([]byte(response))
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
				}
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			client, mux, tearDown := setupClientTest()
			defer tearDown()

			mux.HandleFunc("/", test.handler)

			sessionID, err := client.Login()
			assert.Error(t, err)
			assert.Equal(t, "", sessionID)
		})
	}
}

func TestClient_Logout(t *testing.T) {
	client, mux, tearDown := setupClientTest()
	defer tearDown()

	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		raw, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}

		if string(raw) != `{"action":"logout","param":{"customernumber":"a","apikey":"b","apisessionid":"session-id"}}` {
			http.Error(rw, fmt.Sprintf("invalid request body: %s", string(raw)), http.StatusBadRequest)
		}

		response := `
			{
				"serverrequestid": "request-id",
				"clientrequestid": "",
				"action": "logout",
				"status": "success",
				"statuscode": 2000,
				"shortmessage": "Logout successful",
				"longmessage": "Session has been terminated successful.",
				"responsedata": ""
			}`
		_, err = rw.Write([]byte(response))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	})

	err := client.Logout("session-id")
	require.NoError(t, err)
}

func TestClient_Logout_errors(t *testing.T) {
	testCases := []struct {
		desc    string
		handler func(rw http.ResponseWriter, req *http.Request)
	}{
		{
			desc: "HTTP error",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				http.Error(rw, "error message", http.StatusInternalServerError)
			},
		},
		{
			desc: "API error",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				response := `
					{
						"serverrequestid":"YxTr4EzdbJ101T211zR4yzUEMVE",
						"clientrequestid":"",
						"action":"logout",
						"status":"error",
						"statuscode":4013,
						"shortmessage":"Validation Error.",
						"longmessage":"Message is empty.",
						"responsedata":""
					}`
				_, err := rw.Write([]byte(response))
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
				}
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			client, mux, tearDown := setupClientTest()
			defer tearDown()

			mux.HandleFunc("/", test.handler)

			err := client.Logout("session-id")
			require.Error(t, err)
		})
	}
}

func TestClient_GetDNSRecords(t *testing.T) {
	client, mux, tearDown := setupClientTest()
	defer tearDown()

	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		raw, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}

		if string(raw) != `{"action":"infoDnsRecords","param":{"domainname":"example.com","customernumber":"a","apikey":"b","apisessionid":"api-session-id"}}` {
			http.Error(rw, fmt.Sprintf("invalid request body: %s", string(raw)), http.StatusBadRequest)
		}

		response := `
			{
			  "serverrequestid":"srv-request-id",
			  "clientrequestid":"",
			  "action":"infoDnsRecords",
			  "status":"success",
			  "statuscode":2000,
			  "shortmessage":"Login successful",
			  "longmessage":"Session has been created successful.",
			  "responsedata":{
			    "apisessionid":"api-session-id",
			    "dnsrecords":[
			      {
			        "id":"1",
			        "hostname":"example.com",
			        "type":"TXT",
			        "priority":"1",
			        "destination":"bGVnbzE=",
			        "state":"yes",
			        "ttl":300
			      },
			      {
			        "id":"2",
			        "hostname":"example2.com",
			        "type":"TXT",
			        "priority":"1",
			        "destination":"bGVnbw==",
			        "state":"yes",
			        "ttl":300
			      }
			    ]
			  }
			}`
		_, err = rw.Write([]byte(response))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	})

	expected := []DNSRecord{{
		ID:           1,
		Hostname:     "example.com",
		RecordType:   "TXT",
		Priority:     "1",
		Destination:  "bGVnbzE=",
		DeleteRecord: false,
		State:        "yes",
		TTL:          300,
	}, {
		ID:           2,
		Hostname:     "example2.com",
		RecordType:   "TXT",
		Priority:     "1",
		Destination:  "bGVnbw==",
		DeleteRecord: false,
		State:        "yes",
		TTL:          300,
	}}

	records, err := client.GetDNSRecords("example.com", "api-session-id")
	require.NoError(t, err)

	assert.Equal(t, expected, records)
}

func TestClient_GetDNSRecords_errors(t *testing.T) {
	testCases := []struct {
		desc    string
		handler func(rw http.ResponseWriter, req *http.Request)
	}{
		{
			desc: "HTTP error",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				http.Error(rw, "error message", http.StatusInternalServerError)
			},
		},
		{
			desc: "API error",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				response := `
					{
						"serverrequestid":"YxTr4EzdbJ101T211zR4yzUEMVE",
						"clientrequestid":"",
						"action":"infoDnsRecords",
						"status":"error",
						"statuscode":4013,
						"shortmessage":"Validation Error.",
						"longmessage":"Message is empty.",
						"responsedata":""
					}`
				_, err := rw.Write([]byte(response))
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
				}
			},
		},
		{
			desc: "responsedata marshaling error",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				raw, err := ioutil.ReadAll(req.Body)
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
				}

				if string(raw) != `{"action":"infoDnsRecords","param":{"domainname":"example.com","customernumber":"a","apikey":"b","apisessionid":"api-session-id"}}` {
					http.Error(rw, fmt.Sprintf("invalid request body: %s", string(raw)), http.StatusBadRequest)
				}

				response := `
			{
			  "serverrequestid":"srv-request-id",
			  "clientrequestid":"",
			  "action":"infoDnsRecords",
			  "status":"success",
			  "statuscode":2000,
			  "shortmessage":"Login successful",
			  "longmessage":"Session has been created successful.",
			  "responsedata":""
			}`
				_, err = rw.Write([]byte(response))
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
				}
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			client, mux, tearDown := setupClientTest()
			defer tearDown()

			mux.HandleFunc("/", test.handler)

			records, err := client.GetDNSRecords("example.com", "api-session-id")
			require.Error(t, err)
			assert.Empty(t, records)
		})
	}
}

func TestLiveClientAuth(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	// Setup
	envTest.RestoreEnv()

	client, err := NewClient(
		envTest.GetValue("NETCUP_CUSTOMER_NUMBER"),
		envTest.GetValue("NETCUP_API_KEY"),
		envTest.GetValue("NETCUP_API_PASSWORD"))
	require.NoError(t, err)

	for i := 1; i < 4; i++ {
		i := i
		t.Run("Test_"+strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()

			sessionID, err := client.Login()
			require.NoError(t, err)

			err = client.Logout(sessionID)
			require.NoError(t, err)
		})
	}

}

func TestLiveClientGetDnsRecords(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	// Setup
	envTest.RestoreEnv()

	client, err := NewClient(
		envTest.GetValue("NETCUP_CUSTOMER_NUMBER"),
		envTest.GetValue("NETCUP_API_KEY"),
		envTest.GetValue("NETCUP_API_PASSWORD"))
	require.NoError(t, err)

	sessionID, err := client.Login()
	require.NoError(t, err)

	fqdn, _, _ := acme.DNS01Record(envTest.GetDomain(), "123d==")

	zone, err := acme.FindZoneByFqdn(fqdn, acme.RecursiveNameservers)
	require.NoError(t, err, "error finding DNSZone")

	zone = acme.UnFqdn(zone)

	// TestMethod
	_, err = client.GetDNSRecords(zone, sessionID)
	require.NoError(t, err)

	// Tear down
	err = client.Logout(sessionID)
	require.NoError(t, err)
}

func TestLiveClientUpdateDnsRecord(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	// Setup
	envTest.RestoreEnv()

	client, err := NewClient(
		envTest.GetValue("NETCUP_CUSTOMER_NUMBER"),
		envTest.GetValue("NETCUP_API_KEY"),
		envTest.GetValue("NETCUP_API_PASSWORD"))
	require.NoError(t, err)

	sessionID, err := client.Login()
	require.NoError(t, err)

	fqdn, _, _ := acme.DNS01Record(envTest.GetDomain(), "123d==")

	zone, err := acme.FindZoneByFqdn(fqdn, acme.RecursiveNameservers)
	require.NoError(t, err, fmt.Errorf("error finding DNSZone, %v", err))

	hostname := strings.Replace(fqdn, "."+zone, "", 1)

	record := createTxtRecord(hostname, "asdf5678", 120)

	// test
	zone = acme.UnFqdn(zone)

	err = client.UpdateDNSRecord(sessionID, zone, []DNSRecord{record})
	require.NoError(t, err)

	records, err := client.GetDNSRecords(zone, sessionID)
	require.NoError(t, err)

	recordIdx, err := getDNSRecordIdx(records, record)
	require.NoError(t, err)

	assert.Equal(t, record.Hostname, records[recordIdx].Hostname)
	assert.Equal(t, record.RecordType, records[recordIdx].RecordType)
	assert.Equal(t, record.Destination, records[recordIdx].Destination)
	assert.Equal(t, record.DeleteRecord, records[recordIdx].DeleteRecord)

	records[recordIdx].DeleteRecord = true

	// Tear down
	err = client.UpdateDNSRecord(sessionID, envTest.GetDomain(), []DNSRecord{records[recordIdx]})
	require.NoError(t, err, "Did not remove record! Please do so yourself.")

	err = client.Logout(sessionID)
	require.NoError(t, err)
}
