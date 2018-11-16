package acmedns

import (
	"errors"
	"testing"

	"github.com/cpu/goacmedns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// errorClientErr is used by the Client mocks that return an error.
	errorClientErr = errors.New("errorClient always errors")
	// errorStorageErr is used by the Storage mocks that return an error.
	errorStorageErr = errors.New("errorStorage always errors")

	// Fixed test data for unit tests.
	egDomain  = "threeletter.agency"
	egFQDN    = "_acme-challenge." + egDomain + "."
	egKeyAuth = "⚷"
	egAccount = goacmedns.Account{
		FullDomain: "acme-dns." + egDomain,
		SubDomain:  "random-looking-junk." + egDomain,
		Username:   "spooky.mulder",
		Password:   "trustno1",
	}
)

// mockClient is a mock implementing the acmeDNSClient interface that always
// returns a fixed goacmedns.Account from calls to Register.
type mockClient struct {
	mockAccount goacmedns.Account
}

// UpdateTXTRecord does nothing.
func (c mockClient) UpdateTXTRecord(_ goacmedns.Account, _ string) error {
	return nil
}

// RegisterAccount returns c.mockAccount and no errors.
func (c mockClient) RegisterAccount(_ []string) (goacmedns.Account, error) {
	return c.mockAccount, nil
}

// mockUpdateClient is a mock implementing the acmeDNSClient interface that
// tracks the calls to UpdateTXTRecord in the records map.
type mockUpdateClient struct {
	mockClient
	records map[goacmedns.Account]string
}

// UpdateTXTRecord saves a record value to c.records for the given acct.
func (c mockUpdateClient) UpdateTXTRecord(acct goacmedns.Account, value string) error {
	c.records[acct] = value
	return nil
}

// errorRegisterClient is a mock implementing the acmeDNSClient interface that always
// returns errors from errorUpdateClient.
type errorUpdateClient struct {
	mockClient
}

// UpdateTXTRecord always returns an error.
func (c errorUpdateClient) UpdateTXTRecord(_ goacmedns.Account, _ string) error {
	return errorClientErr
}

// errorRegisterClient is a mock implementing the acmeDNSClient interface that always
// returns errors from RegisterAccount.
type errorRegisterClient struct {
	mockClient
}

// RegisterAccount always returns an error.
func (c errorRegisterClient) RegisterAccount(_ []string) (goacmedns.Account, error) {
	return goacmedns.Account{}, errorClientErr
}

// mockStorage is a mock implementing the goacmedns.Storage interface that
// returns static account data and ignores Save.
type mockStorage struct {
	accounts map[string]goacmedns.Account
}

// Save does nothing.
func (m mockStorage) Save() error {
	return nil
}

// Put stores an account for the given domain in m.accounts.
func (m mockStorage) Put(domain string, acct goacmedns.Account) error {
	m.accounts[domain] = acct
	return nil
}

// Fetch retrieves an account for the given domain from m.accounts or returns
// goacmedns.ErrDomainNotFound.
func (m mockStorage) Fetch(domain string) (goacmedns.Account, error) {
	if acct, ok := m.accounts[domain]; ok {
		return acct, nil
	}
	return goacmedns.Account{}, goacmedns.ErrDomainNotFound
}

// errorPutStorage is a mock implementing the goacmedns.Storage interface that
// always returns errors from Put.
type errorPutStorage struct {
	mockStorage
}

// Put always errors.
func (e errorPutStorage) Put(_ string, _ goacmedns.Account) error {
	return errorStorageErr
}

// errorSaveStoragr is a mock implementing the goacmedns.Storage interface that
// always returns errors from Save.
type errorSaveStorage struct {
	mockStorage
}

// Save always errors.
func (e errorSaveStorage) Save() error {
	return errorStorageErr
}

// errorFetchStorage is a mock implementing the goacmedns.Storage interface that
// always returns errors from Fetch.
type errorFetchStorage struct {
	mockStorage
}

// Fetch always errors.
func (e errorFetchStorage) Fetch(_ string) (goacmedns.Account, error) {
	return goacmedns.Account{}, errorStorageErr
}

// TestPresent tests that the ACME-DNS Present function for updating a DNS-01
// challenge response TXT record works as expected.
func TestPresent(t *testing.T) {
	// validAccountStorage is a mockStorage configured to return the egAccount.
	validAccountStorage := mockStorage{
		map[string]goacmedns.Account{
			egDomain: egAccount,
		},
	}
	// validUpdateClient is a mockClient configured with the egAccount that will
	// track TXT updates in a map.
	validUpdateClient := mockUpdateClient{
		mockClient{egAccount},
		make(map[goacmedns.Account]string),
	}

	testCases := []struct {
		Name          string
		Client        acmeDNSClient
		Storage       goacmedns.Storage
		ExpectedError error
	}{
		{
			Name:          "present when client storage returns unexpected error",
			Client:        mockClient{egAccount},
			Storage:       errorFetchStorage{},
			ExpectedError: errorStorageErr,
		},
		{
			Name:   "present when client storage returns ErrDomainNotFound",
			Client: mockClient{egAccount},
			ExpectedError: ErrCNAMERequired{
				Domain: egDomain,
				FQDN:   egFQDN,
				Target: egAccount.FullDomain,
			},
		},
		{
			Name:          "present when client UpdateTXTRecord returns unexpected error",
			Client:        errorUpdateClient{},
			Storage:       validAccountStorage,
			ExpectedError: errorClientErr,
		},
		{
			Name:    "present when everything works",
			Storage: validAccountStorage,
			Client:  validUpdateClient,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			dp, err := NewDNSProviderClient(tc.Client, mockStorage{make(map[string]goacmedns.Account)})
			require.NoError(t, err)

			// override the storage mock if required by the testcase.
			if tc.Storage != nil {
				dp.storage = tc.Storage
			}

			// call Present. The token argument can be garbage because the ACME-DNS
			// provider does not use it.
			err = dp.Present(egDomain, "foo", egKeyAuth)
			if tc.ExpectedError != nil {
				assert.Equal(t, tc.ExpectedError, err)
			} else {
				require.NoError(t, err)
			}
		})
	}

	// Check that the success testcase set a record.
	assert.Len(t, validUpdateClient.records, 1)

	// Check that the success testcase set the right record for the right account.
	assert.Len(t, validUpdateClient.records[egAccount], 43)
}

// TestRegister tests that the ACME-DNS register function works correctly.
func TestRegister(t *testing.T) {
	testCases := []struct {
		Name          string
		Client        acmeDNSClient
		Storage       goacmedns.Storage
		Domain        string
		FQDN          string
		ExpectedError error
	}{
		{
			Name:          "register when acme-dns client returns an error",
			Client:        errorRegisterClient{},
			ExpectedError: errorClientErr,
		},
		{
			Name:          "register when acme-dns storage put returns an error",
			Client:        mockClient{egAccount},
			Storage:       errorPutStorage{mockStorage{make(map[string]goacmedns.Account)}},
			ExpectedError: errorStorageErr,
		},
		{
			Name:          "register when acme-dns storage save returns an error",
			Client:        mockClient{egAccount},
			Storage:       errorSaveStorage{mockStorage{make(map[string]goacmedns.Account)}},
			ExpectedError: errorStorageErr,
		},
		{
			Name:   "register when everything works",
			Client: mockClient{egAccount},
			ExpectedError: ErrCNAMERequired{
				Domain: egDomain,
				FQDN:   egFQDN,
				Target: egAccount.FullDomain,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			dp, err := NewDNSProviderClient(tc.Client, mockStorage{make(map[string]goacmedns.Account)})
			require.NoError(t, err)

			// override the storage mock if required by the testcase.
			if tc.Storage != nil {
				dp.storage = tc.Storage
			}

			// Call register for the example domain/fqdn.
			err = dp.register(egDomain, egFQDN)
			if tc.ExpectedError != nil {
				assert.Equal(t, tc.ExpectedError, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
