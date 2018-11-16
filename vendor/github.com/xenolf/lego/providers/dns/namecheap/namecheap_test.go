package namecheap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	envTestUser     = "foo"
	envTestKey      = "bar"
	envTestClientIP = "10.0.0.1"

	tlds = map[string]string{
		"com.au": "com.au",
		"com":    "com",
		"co.uk":  "co.uk",
		"uk":     "uk",
		"edu":    "edu",
		"co.com": "co.com",
		"za.com": "za.com",
	}
)

func TestDNSProvider_getHosts(t *testing.T) {
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			mock := httptest.NewServer(mockServer(&test, t))
			defer mock.Close()

			provider := mockDNSProvider(mock.URL)

			ch, err := newChallenge(test.domain, "", tlds)
			require.NoError(t, err)

			hosts, err := provider.getHosts(ch.sld, ch.tld)
			if test.errString != "" {
				assert.EqualError(t, err, test.errString)
			} else {
				assert.NoError(t, err)
			}

		next1:
			for _, h := range hosts {
				for _, th := range test.hosts {
					if h == th {
						continue next1
					}
				}
				t.Errorf("getHosts case %s unexpected record [%s:%s:%s]", test.name, h.Type, h.Name, h.Address)
			}

		next2:
			for _, th := range test.hosts {
				for _, h := range hosts {
					if h == th {
						continue next2
					}
				}
				t.Errorf("getHosts case %s missing record [%s:%s:%s]", test.name, th.Type, th.Name, th.Address)
			}
		})
	}
}

func TestDNSProvider_setHosts(t *testing.T) {
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			mock := httptest.NewServer(mockServer(&test, t))
			defer mock.Close()

			prov := mockDNSProvider(mock.URL)

			ch, err := newChallenge(test.domain, "", tlds)
			require.NoError(t, err)

			hosts, err := prov.getHosts(ch.sld, ch.tld)
			if test.errString != "" {
				assert.EqualError(t, err, test.errString)
			} else {
				require.NoError(t, err)
			}
			if err != nil {
				return
			}

			err = prov.setHosts(ch.sld, ch.tld, hosts)
			require.NoError(t, err)
		})
	}
}

func TestDNSProvider_Present(t *testing.T) {
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			mock := httptest.NewServer(mockServer(&test, t))
			defer mock.Close()

			prov := mockDNSProvider(mock.URL)
			err := prov.Present(test.domain, "", "dummyKey")
			if test.errString != "" {
				assert.EqualError(t, err, "namecheap: "+test.errString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDNSProvider_CleanUp(t *testing.T) {
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			mock := httptest.NewServer(mockServer(&test, t))
			defer mock.Close()

			prov := mockDNSProvider(mock.URL)
			err := prov.CleanUp(test.domain, "", "dummyKey")
			if test.errString != "" {
				assert.EqualError(t, err, "namecheap: "+test.errString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDomainSplit(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
		tld    string
		sld    string
		host   string
	}{
		{domain: "a.b.c.test.co.uk", valid: true, tld: "co.uk", sld: "test", host: "a.b.c"},
		{domain: "test.co.uk", valid: true, tld: "co.uk", sld: "test"},
		{domain: "test.com", valid: true, tld: "com", sld: "test"},
		{domain: "test.co.com", valid: true, tld: "co.com", sld: "test"},
		{domain: "www.test.com.au", valid: true, tld: "com.au", sld: "test", host: "www"},
		{domain: "www.za.com", valid: true, tld: "za.com", sld: "www"},
		{},
		{domain: "a"},
		{domain: "com"},
		{domain: "co.com"},
		{domain: "co.uk"},
		{domain: "test.au"},
		{domain: "za.com"},
		{domain: "www.za"},
		{domain: "www.test.au"},
		{domain: "www.test.unk"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.domain, func(t *testing.T) {
			valid := true
			ch, err := newChallenge(test.domain, "", tlds)
			if err != nil {
				valid = false
			}

			if test.valid && !valid {
				t.Errorf("Expected '%s' to split", test.domain)
			} else if !test.valid && valid {
				t.Errorf("Expected '%s' to produce error", test.domain)
			}

			if test.valid && valid {
				assertEq(t, "domain", ch.domain, test.domain)
				assertEq(t, "tld", ch.tld, test.tld)
				assertEq(t, "sld", ch.sld, test.sld)
				assertEq(t, "host", ch.host, test.host)
			}
		})
	}
}

func assertEq(t *testing.T, variable, got, want string) {
	if got != want {
		t.Errorf("Expected %s to be '%s' but got '%s'", variable, want, got)
	}
}

func assertHdr(tc *testCase, t *testing.T, values *url.Values) {
	ch, _ := newChallenge(tc.domain, "", tlds)

	assertEq(t, "ApiUser", values.Get("ApiUser"), envTestUser)
	assertEq(t, "ApiKey", values.Get("ApiKey"), envTestKey)
	assertEq(t, "UserName", values.Get("UserName"), envTestUser)
	assertEq(t, "ClientIp", values.Get("ClientIp"), envTestClientIP)
	assertEq(t, "SLD", values.Get("SLD"), ch.sld)
	assertEq(t, "TLD", values.Get("TLD"), ch.tld)
}

func mockServer(tc *testCase, t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			values := r.URL.Query()
			cmd := values.Get("Command")
			switch cmd {
			case "namecheap.domains.dns.getHosts":
				assertHdr(tc, t, &values)
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, tc.getHostsResponse)
			case "namecheap.domains.getTldList":
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, responseGetTlds)
			default:
				t.Errorf("Unexpected GET command: %s", cmd)
			}

		case http.MethodPost:
			err := r.ParseForm()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			values := r.Form
			cmd := values.Get("Command")
			switch cmd {
			case "namecheap.domains.dns.setHosts":
				assertHdr(tc, t, &values)
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tc.setHostsResponse)
			default:
				t.Errorf("Unexpected POST command: %s", cmd)
			}

		default:
			t.Errorf("Unexpected http method: %s", r.Method)
		}
	})
}

func mockDNSProvider(url string) *DNSProvider {
	config := NewDefaultConfig()
	config.BaseURL = url
	config.APIUser = envTestUser
	config.APIKey = envTestKey
	config.ClientIP = envTestClientIP
	config.HTTPClient = &http.Client{Timeout: 60 * time.Second}

	provider, err := NewDNSProviderConfig(config)
	if err != nil {
		panic(err)
	}
	return provider
}

type testCase struct {
	name             string
	domain           string
	hosts            []Record
	errString        string
	getHostsResponse string
	setHostsResponse string
}

var testCases = []testCase{
	{
		name:   "Test:Success:1",
		domain: "test.example.com",
		hosts: []Record{
			{Type: "A", Name: "home", Address: "10.0.0.1", MXPref: "10", TTL: "1799"},
			{Type: "A", Name: "www", Address: "10.0.0.2", MXPref: "10", TTL: "1200"},
			{Type: "AAAA", Name: "a", Address: "::0", MXPref: "10", TTL: "1799"},
			{Type: "CNAME", Name: "*", Address: "example.com.", MXPref: "10", TTL: "1799"},
			{Type: "MXE", Name: "example.com", Address: "10.0.0.5", MXPref: "10", TTL: "1800"},
			{Type: "URL", Name: "xyz", Address: "https://google.com", MXPref: "10", TTL: "1799"},
		},
		getHostsResponse: responseGetHostsSuccess1,
		setHostsResponse: responseSetHostsSuccess1,
	},
	{
		name:   "Test:Success:2",
		domain: "example.com",
		hosts: []Record{
			{Type: "A", Name: "@", Address: "10.0.0.2", MXPref: "10", TTL: "1200"},
			{Type: "A", Name: "www", Address: "10.0.0.3", MXPref: "10", TTL: "60"},
		},
		getHostsResponse: responseGetHostsSuccess2,
		setHostsResponse: responseSetHostsSuccess2,
	},
	{
		name:             "Test:Error:BadApiKey:1",
		domain:           "test.example.com",
		errString:        "API Key is invalid or API access has not been enabled [1011102]",
		getHostsResponse: responseGetHostsErrorBadAPIKey1,
	},
}

var responseGetHostsSuccess1 = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors />
  <Warnings />
  <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" EmailType="MXE" IsUsingOurDNS="true">
      <host HostId="217076" Name="www" Type="A" Address="10.0.0.2" MXPref="10" TTL="1200" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false" />
      <host HostId="217069" Name="home" Type="A" Address="10.0.0.1" MXPref="10" TTL="1799" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false" />
      <host HostId="217071" Name="a" Type="AAAA" Address="::0" MXPref="10" TTL="1799" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false" />
      <host HostId="217075" Name="*" Type="CNAME" Address="example.com." MXPref="10" TTL="1799" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false" />
      <host HostId="217073" Name="example.com" Type="MXE" Address="10.0.0.5" MXPref="10" TTL="1800" AssociatedAppTitle="MXE" FriendlyName="MXE1" IsActive="true" IsDDNSEnabled="false" />
      <host HostId="217077" Name="xyz" Type="URL" Address="https://google.com" MXPref="10" TTL="1799" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
  <Server>PHX01SBAPI01</Server>
  <GMTTimeDifference>--5:00</GMTTimeDifference>
  <ExecutionTime>3.338</ExecutionTime>
</ApiResponse>`

var responseSetHostsSuccess1 = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors />
  <Warnings />
  <RequestedCommand>namecheap.domains.dns.setHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true">
      <Warnings />
    </DomainDNSSetHostsResult>
  </CommandResponse>
  <Server>PHX01SBAPI01</Server>
  <GMTTimeDifference>--5:00</GMTTimeDifference>
  <ExecutionTime>2.347</ExecutionTime>
</ApiResponse>`

var responseGetHostsSuccess2 = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors />
  <Warnings />
  <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" EmailType="MXE" IsUsingOurDNS="true">
      <host HostId="217076" Name="@" Type="A" Address="10.0.0.2" MXPref="10" TTL="1200" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false" />
      <host HostId="217069" Name="www" Type="A" Address="10.0.0.3" MXPref="10" TTL="60" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
  <Server>PHX01SBAPI01</Server>
  <GMTTimeDifference>--5:00</GMTTimeDifference>
  <ExecutionTime>3.338</ExecutionTime>
</ApiResponse>`

var responseSetHostsSuccess2 = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors />
  <Warnings />
  <RequestedCommand>namecheap.domains.dns.setHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true">
      <Warnings />
    </DomainDNSSetHostsResult>
  </CommandResponse>
  <Server>PHX01SBAPI01</Server>
  <GMTTimeDifference>--5:00</GMTTimeDifference>
  <ExecutionTime>2.347</ExecutionTime>
</ApiResponse>`

var responseGetHostsErrorBadAPIKey1 = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response">
  <Errors>
    <Error Number="1011102">API Key is invalid or API access has not been enabled</Error>
  </Errors>
  <Warnings />
  <RequestedCommand />
  <Server>PHX01SBAPI01</Server>
  <GMTTimeDifference>--5:00</GMTTimeDifference>
  <ExecutionTime>0</ExecutionTime>
</ApiResponse>`

var responseGetTlds = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors />
  <Warnings />
  <RequestedCommand>namecheap.domains.getTldList</RequestedCommand>
  <CommandResponse Type="namecheap.domains.getTldList">
    <Tlds>
      <Tld Name="com" NonRealTime="false" MinRegisterYears="1" MaxRegisterYears="10" MinRenewYears="1" MaxRenewYears="10" RenewalMinDays="0" RenewalMaxDays="4000" ReactivateMaxDays="27" MinTransferYears="1" MaxTransferYears="1" IsApiRegisterable="true" IsApiRenewable="true" IsApiTransferable="true" IsEppRequired="true" IsDisableModContact="false" IsDisableWGAllot="false" IsIncludeInExtendedSearchOnly="false" SequenceNumber="10" Type="GTLD" SubType="" IsSupportsIDN="true" Category="A" SupportsRegistrarLock="true" AddGracePeriodDays="5" WhoisVerification="false" ProviderApiDelete="true" TldState="" SearchGroup="" Registry="">Most recognized top level domain<Categories><TldCategory Name="popular" SequenceNumber="10" /></Categories></Tld>
    </Tlds>
  </CommandResponse>
  <Server>PHX01SBAPI01</Server>
  <GMTTimeDifference>--5:00</GMTTimeDifference>
  <ExecutionTime>0.004</ExecutionTime>
</ApiResponse>`
