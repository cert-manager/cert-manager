// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package cloudflare implements a DNS provider for solving the DNS-01
// challenge using cloudflare DNS.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// CloudFlareAPIURL represents the API endpoint to call.
// TODO: Unexport?
const CloudFlareAPIURL = "https://api.cloudflare.com/client/v4"

// cloudFlareMaxBodySize is the max size of a received response body. The value is arbitrary
// and is chosen to be large enough that any reasonable response would fit.
const cloudFlareMaxBodySize = 1024 * 1024 // 1mb

// DNSProviderType is the Mockable Interface
type DNSProviderType interface {
	makeRequest(ctx context.Context, method, uri string, body io.Reader) (json.RawMessage, error)
}

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	authEmail        string
	authKey          string
	authToken        string

	userAgent string
}

// DNSZone is the Zone-Record returned from Cloudflare (we`ll ignore everything we don't need)
// See https://api.cloudflare.com/#zone-properties
type DNSZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// NewDNSProvider returns a DNSProvider instance configured for cloudflare.
// Credentials must be passed in the environment variables: CLOUDFLARE_EMAIL
// and CLOUDFLARE_API_KEY.
func NewDNSProvider(dns01Nameservers []string, userAgent string) (*DNSProvider, error) {
	email := os.Getenv("CLOUDFLARE_EMAIL")
	key := os.Getenv("CLOUDFLARE_API_KEY")
	return NewDNSProviderCredentials(email, key, "", dns01Nameservers, userAgent)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for cloudflare.
func NewDNSProviderCredentials(email, key, token string, dns01Nameservers []string, userAgent string) (*DNSProvider, error) {
	if (email == "" && key != "") || (key == "" && token == "") {
		return nil, fmt.Errorf("no Cloudflare credential has been given (can be either an API key or an API token)")
	}
	if key != "" && token != "" {
		return nil, fmt.Errorf("the Cloudflare API key and API token cannot be both present simultaneously")
	}
	// Cloudflare uses the X-Auth-Key header for its authentication.
	// However, if the value of the X-Auth-Key header is invalid, the go
	// http library will "helpfully" print out the value to help with
	// debugging. To prevent leaking the X-Auth-Key value into the logs, we
	// first check that the X-Auth-Key header contains a valid value to
	// prevent the Go HTTP library from displaying it.
	if !validHeaderFieldValue(key) {
		return nil, fmt.Errorf("the Cloudflare API key is invalid (does the API key contain a newline?)")
	}

	if !validHeaderFieldValue(token) {
		return nil, fmt.Errorf("the Cloudflare API token is invalid (does the API token contain a newline?)")
	}

	return &DNSProvider{
		authEmail:        email,
		authKey:          key,
		authToken:        token,
		dns01Nameservers: dns01Nameservers,
		userAgent:        userAgent,
	}, nil
}

// FindNearestZoneForFQDN will try to traverse the official Cloudflare API to find the nearest valid Zone.
// It's a replacement for /pkg/issuer/acme/dns/util/wait.go#FindZoneByFqdn
//
//	example.com.                                   ← Zone-Record found for the SLD (in most cases)
//	└── foo.example.com.                           ← Zone-Record could be possibly here, but in this case not.
//	    └── _acme-challenge.foo.example.com.       ← Starting point, the FQDN.
//
// It will try to call the API for each branch (from bottom to top) and see if there's a Zone-Record returned.
// Calling See https://api.cloudflare.com/#zone-list-zones
func FindNearestZoneForFQDN(ctx context.Context, c DNSProviderType, fqdn string) (DNSZone, error) {
	if fqdn == "" {
		return DNSZone{}, fmt.Errorf("FindNearestZoneForFQDN: FQDN-Parameter can't be empty, please specify a domain!")
	}
	mappedFQDN := strings.Split(fqdn, ".")
	nextName := util.UnFqdn(fqdn) // remove the trailing dot
	var lastErr error
	for i := 0; i < len(mappedFQDN)-1; i++ {
		var from, to = len(mappedFQDN[i]) + 1, len(nextName)
		if from > to {
			continue
		}
		if mappedFQDN[i] == "*" { // skip wildcard sub-domain-entries
			nextName = string([]rune(nextName)[from:to])
			continue
		}
		lastErr = nil
		result, err := c.makeRequest(ctx, "GET", "/zones?name="+nextName, nil)
		if err != nil {
			lastErr = err
			continue
		}
		var zones []DNSZone
		err = json.Unmarshal(result, &zones)
		if err != nil {
			return DNSZone{}, err
		}

		if len(zones) > 0 {
			return zones[0], nil // we're returning the first zone found, might need to test that further
		}
		nextName = string([]rune(nextName)[from:to])
	}
	if lastErr != nil {
		return DNSZone{}, fmt.Errorf("while attempting to find Zones for domain %s\n%s", fqdn, lastErr)
	}
	return DNSZone{}, fmt.Errorf("Found no Zones for domain %s (neither in the sub-domain nor in the SLD) please make sure your domain-entries in the config are correct and the API key is correctly setup with Zone.read rights.", fqdn)
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	_, err := c.findTxtRecord(ctx, fqdn, value)
	if err == errNoExistingRecord {
		rec := cloudFlareRecord{
			Type:    "TXT",
			Name:    util.UnFqdn(fqdn),
			Content: value,
			TTL:     120,
		}

		body, err := json.Marshal(rec)
		if err != nil {
			return err
		}

		zoneID, err := c.getHostedZoneID(ctx, fqdn)
		if err != nil {
			return err
		}

		_, err = c.makeRequest(ctx, "POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), bytes.NewReader(body))
		if err != nil {
			return err
		}

		return nil
	}

	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	record, err := c.findTxtRecord(ctx, fqdn, value)
	// Nothing to cleanup
	if err == errNoExistingRecord {
		return nil
	}
	if err != nil {
		return err
	}

	_, err = c.makeRequest(ctx, "DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", record.ZoneID, record.ID), nil)
	if err != nil {
		return err
	}

	return nil
}

func (c *DNSProvider) getHostedZoneID(ctx context.Context, fqdn string) (string, error) {
	hostedZone, err := FindNearestZoneForFQDN(ctx, c, fqdn)
	if err != nil {
		return "", err
	}
	return hostedZone.ID, nil
}

var errNoExistingRecord = errors.New("No existing record found")

func (c *DNSProvider) findTxtRecord(ctx context.Context, fqdn, content string) (*cloudFlareRecord, error) {
	zoneID, err := c.getHostedZoneID(ctx, fqdn)
	if err != nil {
		return nil, err
	}

	result, err := c.makeRequest(
		ctx,
		"GET",
		fmt.Sprintf("/zones/%s/dns_records?per_page=100&type=TXT&name=%s", zoneID, util.UnFqdn(fqdn)),
		nil,
	)
	if err != nil {
		return nil, err
	}

	var records []cloudFlareRecord
	err = json.Unmarshal(result, &records)
	if err != nil {
		return nil, err
	}

	for _, rec := range records {
		if rec.Name == util.UnFqdn(fqdn) && rec.Content == content {
			return &rec, nil
		}
	}

	return nil, errNoExistingRecord
}

func (c *DNSProvider) makeRequest(ctx context.Context, method, uri string, body io.Reader) (json.RawMessage, error) {
	// APIError contains error details for failed requests
	type APIError struct {
		Code       int        `json:"code,omitempty"`
		Message    string     `json:"message,omitempty"`
		ErrorChain []APIError `json:"error_chain,omitempty"`
	}

	// APIResponse represents a response from CloudFlare API
	type APIResponse struct {
		Success bool            `json:"success"`
		Errors  []*APIError     `json:"errors"`
		Result  json.RawMessage `json:"result"`
	}

	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("%s%s", CloudFlareAPIURL, uri), body)
	if err != nil {
		return nil, err
	}

	if c.authEmail != "" {
		req.Header.Set("X-Auth-Email", c.authEmail)
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	} else {
		req.Header.Set("X-Auth-Key", c.authKey)
	}
	req.Header.Set("User-Agent", c.userAgent)

	client := http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("while querying the Cloudflare API for %s %q: %v", method, uri, err)
	}

	defer resp.Body.Close()

	var r APIResponse
	err = json.NewDecoder(io.LimitReader(resp.Body, cloudFlareMaxBodySize)).Decode(&r)
	if err != nil {
		return nil, err
	}

	if !r.Success {
		if len(r.Errors) > 0 {
			errStr := ""
			for _, apiErr := range r.Errors {
				errStr += fmt.Sprintf("\t Error: %d: %s", apiErr.Code, apiErr.Message)
				for _, chainErr := range apiErr.ErrorChain {
					errStr += fmt.Sprintf("<- %d: %s", chainErr.Code, chainErr.Message)
				}
			}
			return nil, fmt.Errorf("while querying the Cloudflare API for %s %q \n%s", method, uri, errStr)
		}
		return nil, fmt.Errorf("while querying the Cloudflare API for %s %q", method, uri)
	}

	return r.Result, nil
}

// cloudFlareRecord represents a CloudFlare DNS record
type cloudFlareRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	ID      string `json:"id,omitempty"`
	TTL     int    `json:"ttl,omitempty"`
	ZoneID  string `json:"zone_id,omitempty"`
}

// following functions are copy-pasted from go's internal
// http server
func validHeaderFieldValue(v string) bool {
	for i := 0; i < len(v); i++ {
		b := v[i]
		if isCTL(b) && !isLWS(b) {
			return false
		}
	}
	return true
}

func isCTL(b byte) bool {
	const del = 0x7f // a CTL
	return b < ' ' || b == del
}

func isLWS(b byte) bool { return b == ' ' || b == '\t' }
