/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package digitalocean

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	doLiveTest bool
	doToken    string
	doDomain   string
)

func init() {
	doToken = os.Getenv("DIGITALOCEAN_TOKEN")
	doDomain = os.Getenv("DIGITALOCEAN_DOMAIN")
	if len(doToken) > 0 && len(doDomain) > 0 {
		doLiveTest = true
	}
}

func TestNewDNSProviderValid(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "")
	_, err := NewDNSProviderCredentials("123", util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "")
	_, err := NewDNSProvider(util.RecursiveNameservers, "cert-manager-test")
	assert.EqualError(t, err, "DigitalOcean token missing")
}

func TestDigitalOceanPresent(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(doToken, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)

	err = provider.Present(t.Context(), doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestDigitalOceanCleanUp(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(doToken, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)

	err = provider.CleanUp(t.Context(), doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestNewDNSProviderFromOptions(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T)
		options []DNSProviderOption
		wantErr string
	}{
		{
			name: "valid token",
			options: []DNSProviderOption{
				Token("123"),
				Nameservers(util.RecursiveNameservers),
				UserAgent("cert-manager-test"),
				Resolver(util.NewCachingResolver()),
			},
		},
		{
			name: "missing token",
			options: []DNSProviderOption{
				Nameservers(util.RecursiveNameservers),
				UserAgent("cert-manager-test"),
				Resolver(util.NewCachingResolver()),
			},
			wantErr: "DigitalOcean token missing",
		},
		{
			name: "missing resolver",
			options: []DNSProviderOption{
				Token("123"),
				Nameservers(util.RecursiveNameservers),
			},
			wantErr: "resolver is required",
		},
		{
			name: "missing nameservers",
			options: []DNSProviderOption{
				Token("123"),
				Resolver(util.NewCachingResolver()),
			},
			wantErr: "nameservers is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}
			_, err := NewDNSProviderFromOptions(t.Context(), tt.options...)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

// fakeResolver is a util.Resolver stub that always resolves to a fixed
// zone, so tests don't need to perform real DNS lookups.
type fakeResolver struct {
	zone string
}

func (f fakeResolver) FindZoneByFQDN(_ context.Context, _ string, _ []string) (string, error) {
	return f.zone, nil
}

func (f fakeResolver) LookupAuthoritativeNameservers(_ context.Context, _ string, _ []string) ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f fakeResolver) CheckTXTRecordPropagation(_ context.Context, _, _ string, _ []string, _ util.UseAuthoritative) (bool, error) {
	return false, fmt.Errorf("not implemented")
}

// fakeDORecord mirrors the subset of the DigitalOcean domain record JSON
// shape that findTxtRecord relies on.
type fakeDORecord struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
}

// newPaginatedDOServer starts a test server that always serves records in
// pages of pageSize, regardless of the per_page value the client asks
// for. This mimics a worst case where the zone is large enough that even
// a generous, explicit per_page is not enough to see every record on a
// single page, so it specifically exercises the pagination loop in
// findTxtRecord rather than just its larger-than-default page size.
func newPaginatedDOServer(t *testing.T, domain string, allRecords []fakeDORecord, pageSize int) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/v2/domains/%s/records", domain), func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		assert.Equal(t, "TXT", q.Get("type"), "expected findTxtRecord to filter by type=TXT")

		page := 1
		if p := q.Get("page"); p != "" {
			var err error
			page, err = parsePage(p)
			if !assert.NoError(t, err) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		start := (page - 1) * pageSize
		end := start + pageSize
		if start > len(allRecords) {
			start = len(allRecords)
		}
		if end > len(allRecords) {
			end = len(allRecords)
		}

		pageRecords := allRecords[start:end]

		pages := map[string]string{}
		if start > 0 {
			pages["prev"] = fmt.Sprintf("/v2/domains/%s/records?page=%d", domain, page-1)
		}
		if end < len(allRecords) {
			pages["next"] = fmt.Sprintf("/v2/domains/%s/records?page=%d", domain, page+1)
			pages["last"] = fmt.Sprintf("/v2/domains/%s/records?page=%d", domain, (len(allRecords)+pageSize-1)/pageSize)
		}

		links := map[string]any{}
		if len(pages) > 0 {
			links["pages"] = pages
		}

		resp := map[string]any{
			"domain_records": pageRecords,
			"links":          links,
			"meta":           map[string]any{"total": len(allRecords)},
		}

		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(resp))
	})

	return httptest.NewServer(mux)
}

func parsePage(s string) (int, error) {
	var page int
	_, err := fmt.Sscanf(s, "%d", &page)
	return page, err
}

func newTestProvider(t *testing.T, serverURL, zone string) *DNSProvider {
	t.Helper()

	provider, err := NewDNSProviderFromOptions(t.Context(),
		Token("fake-token"),
		Nameservers(util.RecursiveNameservers),
		UserAgent("cert-manager-test"),
		Resolver(fakeResolver{zone: zone}),
	)
	require.NoError(t, err)

	baseURL, err := url.Parse(serverURL + "/")
	require.NoError(t, err)
	provider.client.BaseURL = baseURL

	return provider
}

// TestFindTxtRecordPagination is a regression test for
// https://github.com/cert-manager/cert-manager/issues/9099: a challenge
// TXT record sitting beyond the first page of results must still be
// found (and therefore still be cleaned up), no matter how many other
// TXT records exist in the zone.
func TestFindTxtRecordPagination(t *testing.T) {
	const (
		domain = "example.com"
		zone   = "example.com."
		fqdn   = "_acme-challenge.example.com."
	)

	// Build a zone with far more than one page's worth of TXT records.
	// The matching challenge record is deliberately the very last one,
	// so it only appears on the final page.
	var allRecords []fakeDORecord
	for i := 0; i < 24; i++ {
		allRecords = append(allRecords, fakeDORecord{
			ID:   1000 + i,
			Type: "TXT",
			Name: fmt.Sprintf("unrelated-record-%d", i),
			Data: "irrelevant",
		})
	}
	const challengeRecordID = 9999
	allRecords = append(allRecords, fakeDORecord{
		ID:   challengeRecordID,
		Type: "TXT",
		Name: "_acme-challenge",
		Data: "the-challenge-value",
	})

	// Page size of 10 forces the loop to walk three pages to find the
	// last record, exercising the pagination logic end-to-end.
	server := newPaginatedDOServer(t, domain, allRecords, 10)
	defer server.Close()

	provider := newTestProvider(t, server.URL, zone)

	records, err := provider.findTxtRecord(t.Context(), zone, fqdn)
	require.NoError(t, err)
	require.Len(t, records, 1, "expected exactly one matching TXT record to be found across all pages")
	assert.Equal(t, challengeRecordID, records[0].ID)
	assert.Equal(t, "the-challenge-value", records[0].Data)
}

// TestFindTxtRecordPaginationNoMatch ensures that findTxtRecord still
// paginates through every page even when no record matches, and returns
// an empty (not partial) result without error.
func TestFindTxtRecordPaginationNoMatch(t *testing.T) {
	const (
		domain = "example.com"
		zone   = "example.com."
	)

	var allRecords []fakeDORecord
	for i := 0; i < 35; i++ {
		allRecords = append(allRecords, fakeDORecord{
			ID:   2000 + i,
			Type: "TXT",
			Name: fmt.Sprintf("unrelated-record-%d", i),
			Data: "irrelevant",
		})
	}

	server := newPaginatedDOServer(t, domain, allRecords, 10)
	defer server.Close()

	provider := newTestProvider(t, server.URL, zone)

	records, err := provider.findTxtRecord(t.Context(), zone, "_acme-challenge.example.com.")
	require.NoError(t, err)
	assert.Empty(t, records)
}
