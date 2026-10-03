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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync"
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

// testDomain and testZone are used by every fake-server-backed test below;
// none of them need a different domain, so it's a shared constant rather
// than a parameter threaded through helpers that would always receive the
// same value.
const (
	testDomain = "example.com"
	testZone   = testDomain + "."
)

// fakeDORecord mirrors the subset of the DigitalOcean domain record JSON
// shape that findTxtRecord relies on.
type fakeDORecord struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
}

// fullName reconstructs the fully-qualified name DigitalOcean's `name`
// list filter matches against from a record's (relative) Name field, the
// same way the real API does: apex records are stored with Name "@" and
// everything else is relative to testDomain.
func (r fakeDORecord) fullName() string {
	if r.Name == "@" {
		return testDomain
	}
	return r.Name + "." + testDomain
}

// fakeDOServer is a minimal in-memory stand-in for the DigitalOcean
// domain records API. It supports the one operation findTxtRecord needs:
// listing records filtered by type+name (paginated in pages of pageSize,
// regardless of the per_page the client asks for, to exercise
// findTxtRecord's pagination loop even though it's rarely needed against
// the real API).
type fakeDOServer struct {
	t        *testing.T
	pageSize int

	mu      sync.Mutex
	records []fakeDORecord
}

func newFakeDOServer(t *testing.T, records []fakeDORecord, pageSize int) *httptest.Server {
	t.Helper()

	s := &fakeDOServer{t: t, records: records, pageSize: pageSize}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/domains/"+testDomain+"/records", s.handleList)

	return httptest.NewServer(mux)
}

func (s *fakeDOServer) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	assert.Equal(s.t, "TXT", q.Get("type"), "expected findTxtRecord to filter by type=TXT")

	name := q.Get("name")
	require.NotEmpty(s.t, name, "expected findTxtRecord to filter by name server-side")

	s.mu.Lock()
	var matched []fakeDORecord
	for _, rec := range s.records {
		if rec.Type == "TXT" && rec.fullName() == name {
			matched = append(matched, rec)
		}
	}
	s.mu.Unlock()

	page := 1
	if p := q.Get("page"); p != "" {
		var err error
		page, err = strconv.Atoi(p)
		if !assert.NoError(s.t, err) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	start := min((page-1)*s.pageSize, len(matched))
	end := min(start+s.pageSize, len(matched))
	pageRecords := matched[start:end]

	pages := map[string]string{}
	if start > 0 {
		pages["prev"] = fmt.Sprintf("/v2/domains/%s/records?page=%d", testDomain, page-1)
	}
	if end < len(matched) {
		pages["next"] = fmt.Sprintf("/v2/domains/%s/records?page=%d", testDomain, page+1)
		pages["last"] = fmt.Sprintf("/v2/domains/%s/records?page=%d", testDomain, (len(matched)+s.pageSize-1)/s.pageSize)
	}

	links := map[string]any{}
	if len(pages) > 0 {
		links["pages"] = pages
	}

	resp := map[string]any{
		"domain_records": pageRecords,
		"links":          links,
		"meta":           map[string]any{"total": len(matched)},
	}

	w.Header().Set("Content-Type", "application/json")
	assert.NoError(s.t, json.NewEncoder(w).Encode(resp))
}

func newTestProvider(t *testing.T, serverURL string) *DNSProvider {
	t.Helper()

	provider, err := NewDNSProviderCredentials("fake-token", util.RecursiveNameservers, "cert-manager-test")
	require.NoError(t, err)

	baseURL, err := url.Parse(serverURL + "/")
	require.NoError(t, err)
	provider.client.BaseURL = baseURL

	return provider
}

// TestFindTxtRecordFiltersServerSide checks that findTxtRecord only
// returns records that share fqdn's name, relying on the fake server to
// enforce the name filter the same way the real DigitalOcean API does.
func TestFindTxtRecordFiltersServerSide(t *testing.T) {
	const fqdn = "_acme-challenge.example.com."

	records := []fakeDORecord{
		{ID: 1, Type: "TXT", Name: "unrelated", Data: "irrelevant"},
		{ID: 2, Type: "TXT", Name: "_acme-challenge", Data: "the-challenge-value"},
		{ID: 3, Type: "TXT", Name: "unrelated", Data: "also-irrelevant"},
	}

	server := newFakeDOServer(t, records, 200)
	defer server.Close()

	provider := newTestProvider(t, server.URL)

	got, err := provider.findTxtRecord(t.Context(), testZone, fqdn)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 2, got[0].ID)
	assert.Equal(t, "the-challenge-value", got[0].Data)
}

// TestFindTxtRecordPagination is a regression test for
// https://github.com/cert-manager/cert-manager/issues/9099, adapted for
// the server-side name filter: even in the unlikely event that a single
// name has more matching TXT records than fit on one page, findTxtRecord
// must still walk every page and return all of them, not just the first
// pageSize.
func TestFindTxtRecordPagination(t *testing.T) {
	const fqdn = "_acme-challenge.example.com."

	var records []fakeDORecord
	for i := range 25 {
		records = append(records, fakeDORecord{
			ID:   1000 + i,
			Type: "TXT",
			Name: "_acme-challenge",
			Data: fmt.Sprintf("challenge-value-%d", i),
		})
	}
	// A same-type, differently-named record must never be returned, even
	// though the fake server would otherwise happily paginate it too.
	records = append(records, fakeDORecord{ID: 2000, Type: "TXT", Name: "unrelated", Data: "irrelevant"})

	// Page size of 10 forces the loop to walk three pages of matching
	// records, exercising the pagination safety net end-to-end.
	server := newFakeDOServer(t, records, 10)
	defer server.Close()

	provider := newTestProvider(t, server.URL)

	got, err := provider.findTxtRecord(t.Context(), testZone, fqdn)
	require.NoError(t, err)
	require.Len(t, got, 25, "expected every same-name record to be found across all pages")
	for _, record := range got {
		assert.Equal(t, "_acme-challenge", record.Name)
	}
}

// TestFindTxtRecordNoMatch ensures that findTxtRecord returns an empty
// result without error when nothing matches the name filter.
func TestFindTxtRecordNoMatch(t *testing.T) {
	records := []fakeDORecord{
		{ID: 1, Type: "TXT", Name: "unrelated", Data: "irrelevant"},
	}

	server := newFakeDOServer(t, records, 200)
	defer server.Close()

	provider := newTestProvider(t, server.URL)

	got, err := provider.findTxtRecord(t.Context(), testZone, "_acme-challenge.example.com.")
	require.NoError(t, err)
	assert.Empty(t, got)
}
