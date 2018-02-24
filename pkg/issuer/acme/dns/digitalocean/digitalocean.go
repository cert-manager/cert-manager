// Package digitalocean implements a DNS provider for solving the DNS-01
// challenge using digitalocean DNS.
package digitalocean

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// DigitalOceanAPIURL represents the API endpoint to call.
const DigitalOceanAPIURL = "https://api.digitalocean.com/v2"

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	authToken string
}

// NewDNSProvider returns a DNSProvider instance configured for digitalocean.
// The access token must be passed in the environment variable DIGITALOCEAN_TOKEN
func NewDNSProvider() (*DNSProvider, error) {
	token := os.Getenv("DIGITALOCEAN_TOKEN")
	return NewDNSProviderCredentials(token)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for digitalocean.
func NewDNSProviderCredentials(token string) (*DNSProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("DigitalOcean token missing")
	}

	return &DNSProvider{
		authToken: token,
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, _ := util.DNS01Record(domain, keyAuth)

	// if DigitalOcean does not have this zone then we will find out later
	zoneName, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return err
	}

	rec := digitalOceanRecord{
		Type: "TXT",
		Name: util.UnFqdn(fqdn),
		Data: value,
		TTL:  120,
	}

	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	_, err = c.makeRequest("POST", fmt.Sprintf("/domains/%s/records", util.UnFqdn(zoneName)), bytes.NewReader(body))
	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _ := util.DNS01Record(domain, keyAuth)

	zoneName, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)

	record, err := c.findTxtRecord(fqdn)
	if err != nil {
		return err
	}

	_, err = c.makeRequest("DELETE", fmt.Sprintf("/domains/%s/records/%d", util.UnFqdn(zoneName), record.ID), nil)
	if err != nil {
		return err
	}

	return nil
}

func (c *DNSProvider) findTxtRecord(fqdn string) (*digitalOceanRecord, error) {

	// APIDomainRecordsResponse represents a domain records list response from the digitalocean API
	type APIDomainRecordsResponse struct {
		DomainRecords []digitalOceanRecord `json:"domain_records"`
	}

	zoneName, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return nil, err
	}

	result, err := c.makeRequest(
		"GET",
		fmt.Sprintf("/domains/%s/records?per_page=1000&type=TXT&name=%s", util.UnFqdn(zoneName), util.UnFqdn(fqdn)),
		nil,
	)
	if err != nil {
		return nil, err
	}

	var records APIDomainRecordsResponse
	err = json.Unmarshal(result, &records)
	if err != nil {
		return nil, err
	}

	for _, rec := range records.DomainRecords {
		if rec.Name == util.UnFqdn(fqdn) {
			return &rec, nil
		}
	}

	return nil, fmt.Errorf("No existing record found for %s", fqdn)
}

func (c *DNSProvider) makeRequest(method, uri string, body io.Reader) (json.RawMessage, error) {
	// APIError contains error details for failed requests
	type APIError struct {
		Code    int    `json:"code,omitempty"`
		Message string `json:"message,omitempty"`
	}

	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", DigitalOceanAPIURL, uri), body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.authToken))
	req.Header.Set("Content-Type", "application/json")
	//req.Header.Set("User-Agent", userAgent())

	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error querying DigitalOcean API -> %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var r APIError

		err = json.NewDecoder(resp.Body).Decode(&r)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("DigitalOcean API Error \n%d: %s", r.Code, r.Message)
	}

	if method != "DELETE" {
		var res json.RawMessage
		err = json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			return nil, err
		}

		return res, nil
	}

	return nil, nil
}

// digitalOceanRecord represents a DigitalOcean DNS record
type digitalOceanRecord struct {
	ID   int    `json:"id,omitempty"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl,omitempty"`
}
