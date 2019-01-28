// Package pdns implements a DNS provider for solving the DNS-01 challenge using PowerDNS nameserver.
package pdns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// Config is used to configure the creation of the DNSProvider
type Config struct {
	APIKey             string
	Host               *url.URL
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
	HTTPClient         *http.Client
	DNS01Nameservers   []string
}

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	apiVersion int
	config     *Config
}

func NewDNSProvider(host, apiKey string, ttl int, timeout, propagationTimeout, pollingInterval time.Duration, dns01Nameservers []string) (*DNSProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("pdns: API key missing")
	}

	if host == "" {
		return nil, fmt.Errorf("pdns: API URL missing")
	}

	hostURL, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("pdns: Error parsing host - %s", err.Error())
	}

	if hostURL.Host == "" {
		return nil, fmt.Errorf("pdns: API URL missing")
	}

	if ttl <= 0 {
		ttl = 60
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if propagationTimeout <= 0 {
		propagationTimeout = 120 * time.Second
	}

	if pollingInterval <= 0 {
		pollingInterval = 2 * time.Second
	}

	return NewDNSProviderConfig(&Config{
		Host:               hostURL,
		APIKey:             apiKey,
		TTL:                ttl,
		PropagationTimeout: propagationTimeout,
		PollingInterval:    pollingInterval,
		DNS01Nameservers:   dns01Nameservers,
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
	})
}

// NewDNSProviderConfig return a DNSProvider instance configured for pdns.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("pdns: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" {
		return nil, fmt.Errorf("pdns: API key missing")
	}

	if config.Host == nil || config.Host.Host == "" {
		return nil, fmt.Errorf("pdns: API URL missing")
	}

	d := &DNSProvider{config: config}

	apiVersion, err := d.getAPIVersion()
	if err != nil {
		glog.Warningf("pdns: failed to get API version %v", err)
	}
	d.apiVersion = apiVersion

	return d, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge
func (d *DNSProvider) Present(domain, fqdn, value string) error {
	zone, err := d.getHostedZone(fqdn)
	if err != nil {
		return fmt.Errorf("pdns: %v", err)
	}

	name := fqdn

	// pre-v1 API wants non-fqdn
	if d.apiVersion == 0 {
		name = util.UnFqdn(fqdn)
	}

	rec := Record{
		Content:  "\"" + value + "\"",
		Disabled: false,

		// pre-v1 API
		Type: "TXT",
		Name: name,
		TTL:  d.config.TTL,
	}

	rrsets := rrSets{
		RRSets: []rrSet{
			{
				Name:       name,
				ChangeType: "REPLACE",
				Type:       "TXT",
				Kind:       "Master",
				TTL:        d.config.TTL,
				Records:    []Record{rec},
			},
		},
	}

	body, err := json.Marshal(rrsets)
	if err != nil {
		return fmt.Errorf("pdns: %v", err)
	}

	_, err = d.sendRequest(http.MethodPatch, zone.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pdns: %v", err)
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (d *DNSProvider) CleanUp(domain, fqdn, value string) error {
	zone, err := d.getHostedZone(fqdn)
	if err != nil {
		return fmt.Errorf("pdns: %v", err)
	}

	set, err := d.findTxtRecord(fqdn)
	if err != nil {
		return fmt.Errorf("pdns: %v", err)
	}

	rrsets := rrSets{
		RRSets: []rrSet{
			{
				Name:       set.Name,
				Type:       set.Type,
				ChangeType: "DELETE",
			},
		},
	}
	body, err := json.Marshal(rrsets)
	if err != nil {
		return fmt.Errorf("pdns: %v", err)
	}

	_, err = d.sendRequest(http.MethodPatch, zone.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pdns: %v", err)
	}
	return nil
}
