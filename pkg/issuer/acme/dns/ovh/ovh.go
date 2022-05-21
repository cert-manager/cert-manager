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

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/go-logr/logr"
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
	recordIDs   map[string]*zoneResquest
	recordIDsMu sync.Mutex
	log         logr.Logger
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for OVH
// Credentials must be passed in the environment variable:
// OVH_ENDPOINT : it must be ovh-eu or ovh-ca
// OVH_APPLICATION_KEY
// OVH_APPLICATION_SECRET
// OVH_CONSUMER_KEY
func NewDNSProviderCredentials(endpoint, applicationKey, applicationSecret, consumerKey string, dns01Nameservers []string) (*DNSProvider, error) {
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
		recordIDs: make(map[string]*zoneResquest),
		log:       logs.Log.WithName("ovh-dns"),
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

type zoneResquest struct {
	ZoneName  string
	SubDomain string
	ID        int
}

func NewZoneRequestFromFQDN(fqdn string) (*zoneResquest, error) {
	authZone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return nil, fmt.Errorf("ovh: could not determine zone for fqdn: '%s'. %s", fqdn, err)
	}

	authZone = util.UnFqdn(authZone)
	subDomain := extractRecordName(fqdn, authZone)

	return &zoneResquest{authZone, subDomain, 0}, nil
}

func (z *zoneResquest) BaseURL() string {
	return fmt.Sprintf("/domain/zone/%s/record", z.ZoneName)
}

func (z *zoneResquest) FetchURL() string {
	if z.ID == 0 {
		return fmt.Sprintf("%s?fieldType=TXT&subDomain=%s", z.BaseURL(), z.SubDomain)
	}
	return fmt.Sprintf("%s/%d", z.BaseURL(), z.ID)
}

func (z *zoneResquest) CrudURL() string {
	if z.ID == 0 {
		return z.BaseURL()
	} else {
		return fmt.Sprintf("%s/%d", z.BaseURL(), z.ID)
	}
}

func (z *zoneResquest) LogItems() (result []interface{}) {
	result = []interface{}{"zone", z.ZoneName, "subDomain", z.SubDomain}
	if z.ID != 0 {
		result = append(result, "id", z.ID)
	}
	return
}

func (z *zoneResquest) RefreshURL() string {
	return fmt.Sprintf("/domain/zone/%s/refresh", z.ZoneName)
}

// txtUpdateRequest updates a DNS record
type txtUpdateRequest struct {
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl"`
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

// Present creates a TXT record to fulfill the dns-01 challenge.
func (c *DNSProvider) Present(domain, fqdn, value string) error {

	// Parse domain name
	zoneRequest, err := NewZoneRequestFromFQDN(fqdn)
	if err != nil {
		return fmt.Errorf("ovh: could not determine zone for domain: '%s'. %s", domain, err)
	}

	var respData txtRecordResponse
	// Getting current record Id
	c.log.V(logs.InfoLevel).Info("getting existing record information", zoneRequest.LogItems()...)
	var fetchData []int

	err = c.client.Get(zoneRequest.FetchURL(), &fetchData)
	if err != nil {
		return fmt.Errorf("ovh: error while fetching existing TXT record: %v", err)
	}

	if len(fetchData) > 0 {
		if len(fetchData) > 1 {
			c.log.V(logs.WarnLevel).Info("More than one txt record", append(zoneRequest.LogItems(), "records", fetchData)...)
		}
		zoneRequest.ID = fetchData[0]

		c.log.V(logs.DebugLevel).Info("getting existing record", zoneRequest.LogItems()...)
		err = c.client.Get(zoneRequest.FetchURL(), &respData)
		if err != nil {
			return fmt.Errorf("ovh: error while fetching existing TXT record: %v", err)
		}

		if respData.Target == value {
			c.log.Info("Value already registered", append(zoneRequest.LogItems(), "value", value)...)
		} else {
			c.log.Info("Updating value of existing record", append(zoneRequest.LogItems(), "oldValue", respData.Target, "newValue", value)...)
			putData := txtUpdateRequest{SubDomain: zoneRequest.SubDomain, Target: value, TTL: respData.TTL}
			err = c.client.Put(zoneRequest.CrudURL(), putData, nil)
			if err != nil {
				return fmt.Errorf("ovh: error while updating existing TXT record: %v", err)
			}
		}
	} else {
		reqData := txtRecordRequest{FieldType: "TXT", SubDomain: zoneRequest.SubDomain, Target: value, TTL: c.config.TTL}

		// Create TXT record
		c.log.V(logs.InfoLevel).Info("creating record", zoneRequest.LogItems()...)
		err = c.client.Post(zoneRequest.CrudURL(), reqData, &respData)
		if err != nil {
			return fmt.Errorf("ovh: error getting existing record value: %v", err)
		}
	}

	// Refresh the zone
	c.log.V(logs.InfoLevel).Info("updating zone", "zone", zoneRequest.ZoneName)
	err = c.client.Post(zoneRequest.RefreshURL(), nil, nil)
	if err != nil {
		return fmt.Errorf("ovh: error when call api to refresh zone: %v", err)
	}

	zoneRequest.ID = respData.ID

	c.recordIDsMu.Lock()
	c.recordIDs[fqdn] = zoneRequest
	c.recordIDsMu.Unlock()

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {

	var zoneRequest *zoneResquest
	var ok bool
	var err error

	c.recordIDsMu.Lock()
	zoneRequest, ok = c.recordIDs[fqdn]
	c.recordIDsMu.Unlock()

	// get the record's unique ID from when we created it
	if !ok {
		c.log.V(logs.WarnLevel).Info("No entry found. fetching API", "fqdn", fqdn)

		zoneRequest, err = NewZoneRequestFromFQDN(fqdn)
		if err != nil {
			return fmt.Errorf("ovh: could not determine zone for domain: '%s'. %s", domain, err)
		}

		// Getting current record Id
		c.log.V(logs.InfoLevel).Info("getting existing record information", zoneRequest.LogItems()...)
		var fetchData []int

		err = c.client.Get(zoneRequest.FetchURL(), &fetchData)
		if err != nil {
			return fmt.Errorf("ovh: error while fetching existing TXT record: %v", err)
		}

		if len(fetchData) == 0 {
			return fmt.Errorf("ovh: unknown record ID for '%s'", fqdn)
		} else {
			zoneRequest.ID = fetchData[0]
		}
	}

	c.log.V(logs.InfoLevel).Info("deleting record", zoneRequest.LogItems()...)
	err = c.client.Delete(zoneRequest.CrudURL(), nil)
	if err != nil {
		return fmt.Errorf("ovh: error when call OVH api to delete challenge record: %v", err)
	}

	// Refresh the zone
	c.log.V(logs.InfoLevel).Info("updating zone", "zone", zoneRequest.ZoneName)
	err = c.client.Post(zoneRequest.RefreshURL(), nil, nil)
	if err != nil {
		return fmt.Errorf("ovh: error when call api to refresh zone: %v", err)
	}

	// Delete record ID from map
	c.recordIDsMu.Lock()
	delete(c.recordIDs, fqdn)
	c.recordIDsMu.Unlock()

	return nil
}

func extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}
