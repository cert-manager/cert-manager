// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package ovh implements a DNS provider for solving the DNS-01
// challenge using OVH.
package ovh

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/ovh/go-ovh/ovh"
)

// OVH API reference:		https://eu.api.ovh.com/
// Create a Token:			https://eu.api.ovh.com/createToken/

// Config is used to configure the creation of the DNSProvider
type Config struct {
	APIEndpoint       string
	ApplicationKey    string
	ApplicationSecret string
	ConsumerKey       string
	DNS01Nameservers  []string
	PollingInterval   time.Duration
	TTL               int
	HTTPClient        *http.Client
}

// NewDefaultConfig returns a default configuration for the DNSProvider
func NewDefaultConfig() *Config {
	return &Config{
		TTL:             120,
		PollingInterval: 2 * time.Second,
		HTTPClient: &http.Client{
			Timeout: ovh.DefaultTimeout,
		},
	}
}

// DNSProvider is an implementation of the util.ChallengeProvider interface
// that uses OVH's REST API to manage TXT records for a domain.
type DNSProvider struct {
	config      *Config
	client      *ovh.Client
	recordIDs   map[string]int
	recordIDsMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for OVH
// Credentials must be passed in the environment variable:
// OVH_ENDPOINT : it must be ovh-eu or ovh-ca
// OVH_APPLICATION_KEY
// OVH_APPLICATION_SECRET
// OVH_CONSUMER_KEY
func NewDNSProvider(endpoint, applicationKey, applicationSecret, consumerKey string, dns01Nameservers []string) (*DNSProvider, error) {
	config := NewDefaultConfig()
	config.APIEndpoint = endpoint
	config.ApplicationKey = applicationKey
	config.ApplicationSecret = applicationSecret
	config.ConsumerKey = consumerKey
	config.DNS01Nameservers = dns01Nameservers

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for OVH.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("ovh: the configuration of the DNS provider is nil")
	}

	if config.APIEndpoint == "" || config.ApplicationKey == "" || config.ApplicationSecret == "" || config.ConsumerKey == "" {
		return nil, fmt.Errorf("ovh: credentials missing")
	}

	client, err := ovh.NewClient(
		config.APIEndpoint,
		config.ApplicationKey,
		config.ApplicationSecret,
		config.ConsumerKey,
	)
	if err != nil {
		return nil, fmt.Errorf("ovh: %v", err)
	}

	client.Client = config.HTTPClient

	return &DNSProvider{
		config:    config,
		client:    client,
		recordIDs: make(map[string]int),
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (c *DNSProvider) Present(domain, token, key string) error {
	fqdn, value, _, err := util.DNS01Record(domain, key, c.config.DNS01Nameservers)

	// Parse domain name
	authZone, err := util.FindZoneByFqdn(util.ToFqdn(domain), util.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("ovh: could not determine zone for domain: '%s'. %s", domain, err)
	}

	authZone = util.UnFqdn(authZone)
	subDomain := c.extractRecordName(fqdn, authZone)

	reqURL := fmt.Sprintf("/domain/zone/%s/record", authZone)
	reqData := txtRecordRequest{FieldType: "TXT", SubDomain: subDomain, Target: value, TTL: c.config.TTL}
	var respData txtRecordResponse

	// Create TXT record
	err = c.client.Post(reqURL, reqData, &respData)
	if err != nil {
		return fmt.Errorf("ovh: error when call api to add record: %v", err)
	}

	// Apply the change
	reqURL = fmt.Sprintf("/domain/zone/%s/refresh", authZone)
	err = c.client.Post(reqURL, nil, nil)
	if err != nil {
		return fmt.Errorf("ovh: error when call api to refresh zone: %v", err)
	}

	c.recordIDsMu.Lock()
	c.recordIDs[fqdn] = respData.ID
	c.recordIDsMu.Unlock()

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, token, key string) error {
	fqdn, _, _, _ := util.DNS01Record(domain, key, c.config.DNS01Nameservers)

	// get the record's unique ID from when we created it
	c.recordIDsMu.Lock()
	recordID, ok := c.recordIDs[fqdn]
	c.recordIDsMu.Unlock()
	if !ok {
		return fmt.Errorf("ovh: unknown record ID for '%s'", fqdn)
	}

	authZone, err := util.FindZoneByFqdn(util.ToFqdn(domain), util.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("ovh: could not determine zone for domain: '%s'. %s", domain, err)
	}

	authZone = util.UnFqdn(authZone)

	reqURL := fmt.Sprintf("/domain/zone/%s/record/%c", authZone, recordID)

	err = c.client.Delete(reqURL, nil)
	if err != nil {
		return fmt.Errorf("ovh: error when call OVH api to delete challenge record: %v", err)
	}

	// Delete record ID from map
	c.recordIDsMu.Lock()
	delete(c.recordIDs, fqdn)
	c.recordIDsMu.Unlock()

	return nil
}

func (c *DNSProvider) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

// txtRecordRequest represents the request body to DO's API to make a TXT record
type txtRecordRequest struct {
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl"`
}

// txtRecordResponse represents a response from DO's API after making a TXT record
type txtRecordResponse struct {
	ID        int    `json:"id"`
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl"`
	Zone      string `json:"zone"`
}
