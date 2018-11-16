package netcup

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"NETCUP_CUSTOMER_NUMBER",
	"NETCUP_API_KEY",
	"NETCUP_API_PASSWORD").
	WithDomain("NETCUP_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"NETCUP_CUSTOMER_NUMBER": "A",
				"NETCUP_API_KEY":         "B",
				"NETCUP_API_PASSWORD":    "C",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"NETCUP_CUSTOMER_NUMBER": "",
				"NETCUP_API_KEY":         "",
				"NETCUP_API_PASSWORD":    "",
			},
			expected: "netcup: some credentials information are missing: NETCUP_CUSTOMER_NUMBER,NETCUP_API_KEY,NETCUP_API_PASSWORD",
		},
		{
			desc: "missing customer number",
			envVars: map[string]string{
				"NETCUP_CUSTOMER_NUMBER": "",
				"NETCUP_API_KEY":         "B",
				"NETCUP_API_PASSWORD":    "C",
			},
			expected: "netcup: some credentials information are missing: NETCUP_CUSTOMER_NUMBER",
		},
		{
			desc: "missing API key",
			envVars: map[string]string{
				"NETCUP_CUSTOMER_NUMBER": "A",
				"NETCUP_API_KEY":         "",
				"NETCUP_API_PASSWORD":    "C",
			},
			expected: "netcup: some credentials information are missing: NETCUP_API_KEY",
		},
		{
			desc: "missing api password",
			envVars: map[string]string{
				"NETCUP_CUSTOMER_NUMBER": "A",
				"NETCUP_API_KEY":         "B",
				"NETCUP_API_PASSWORD":    "",
			},
			expected: "netcup: some credentials information are missing: NETCUP_API_PASSWORD",
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
				require.NotNil(t, p.client)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc     string
		customer string
		key      string
		password string
		expected string
	}{
		{
			desc:     "success",
			customer: "A",
			key:      "B",
			password: "C",
		},
		{
			desc:     "missing credentials",
			expected: "netcup: credentials missing",
		},
		{
			desc:     "missing customer",
			customer: "",
			key:      "B",
			password: "C",
			expected: "netcup: credentials missing",
		},
		{
			desc:     "missing key",
			customer: "A",
			key:      "",
			password: "C",
			expected: "netcup: credentials missing",
		},
		{
			desc:     "missing password",
			customer: "A",
			key:      "B",
			password: "",
			expected: "netcup: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.Customer = test.customer
			config.Key = test.key
			config.Password = test.password

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.client)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestGetDNSRecordIdx(t *testing.T) {
	records := []DNSRecord{
		{
			ID:           12345,
			Hostname:     "asdf",
			RecordType:   "TXT",
			Priority:     "0",
			Destination:  "randomtext",
			DeleteRecord: false,
			State:        "yes",
		},
		{
			ID:           23456,
			Hostname:     "@",
			RecordType:   "A",
			Priority:     "0",
			Destination:  "127.0.0.1",
			DeleteRecord: false,
			State:        "yes",
		},
		{
			ID:           34567,
			Hostname:     "dfgh",
			RecordType:   "CNAME",
			Priority:     "0",
			Destination:  "example.com",
			DeleteRecord: false,
			State:        "yes",
		},
		{
			ID:           45678,
			Hostname:     "fghj",
			RecordType:   "MX",
			Priority:     "10",
			Destination:  "mail.example.com",
			DeleteRecord: false,
			State:        "yes",
		},
	}

	testCases := []struct {
		desc        string
		record      DNSRecord
		expectError bool
	}{
		{
			desc: "simple",
			record: DNSRecord{
				ID:           12345,
				Hostname:     "asdf",
				RecordType:   "TXT",
				Priority:     "0",
				Destination:  "randomtext",
				DeleteRecord: false,
				State:        "yes",
			},
		},
		{
			desc: "wrong Destination",
			record: DNSRecord{
				ID:           12345,
				Hostname:     "asdf",
				RecordType:   "TXT",
				Priority:     "0",
				Destination:  "wrong",
				DeleteRecord: false,
				State:        "yes",
			},
			expectError: true,
		},
		{
			desc: "record type CNAME",
			record: DNSRecord{
				ID:           12345,
				Hostname:     "asdf",
				RecordType:   "CNAME",
				Priority:     "0",
				Destination:  "randomtext",
				DeleteRecord: false,
				State:        "yes",
			},
			expectError: true,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			idx, err := getDNSRecordIdx(records, test.record)
			if test.expectError {
				assert.Error(t, err)
				assert.Equal(t, -1, idx)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, records[idx], test.record)
			}
		})
	}
}

func TestLivePresentAndCleanup(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	p, err := NewDNSProvider()
	require.NoError(t, err)

	fqdn, _, _ := acme.DNS01Record(envTest.GetDomain(), "123d==")

	zone, err := acme.FindZoneByFqdn(fqdn, acme.RecursiveNameservers)
	require.NoError(t, err, "error finding DNSZone")

	zone = acme.UnFqdn(zone)

	testCases := []string{
		zone,
		"sub." + zone,
		"*." + zone,
		"*.sub." + zone,
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("domain(%s)", tc), func(t *testing.T) {
			err = p.Present(tc, "987d", "123d==")
			require.NoError(t, err)

			err = p.CleanUp(tc, "987d", "123d==")
			require.NoError(t, err, "Did not clean up! Please remove record yourself.")
		})
	}
}
