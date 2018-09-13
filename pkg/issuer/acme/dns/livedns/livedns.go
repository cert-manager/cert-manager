package livedns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/log"
	"github.com/xenolf/lego/platform/config/env"
)

// Gandi API reference:       http://doc.livedns.gandi.net/

var (
	// endpoint is the Gandi API endpoint used by Present and
	// CleanUp. It is overridden during tests.
	endpoint = "https://dns.api.gandi.net/api/v5"

	// findZoneByFqdn determines the DNS zone of an fqdn. It is overridden
	// during tests.
	findZoneByFqdn = acme.FindZoneByFqdn
)

// inProgressInfo contains information about an in-progress challenge
type inProgressInfo struct {
	fieldName string
	authZone  string
}

// DNSProvider is an implementation of the
// acme.ChallengeProviderTimeout interface that uses Gandi's LiveDNS
// API to manage TXT records for a domain.
type DNSProvider struct {
	apiKey          string
	inProgressFQDNs map[string]inProgressInfo
	inProgressMu    sync.Mutex
	client          *http.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Gandi.
// Credentials must be passed in the environment variable: GANDIV5_API_KEY.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get("GANDIV5_API_KEY")
	if err != nil {
		return nil, fmt.Errorf("GandiDNS: %v", err)
	}

	return NewDNSProviderCredentials(values["GANDIV5_API_KEY"])
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for Gandi.
func NewDNSProviderCredentials(apiKey string) (*DNSProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("Gandi DNS: No Gandi API Key given")
	}
	return &DNSProvider{
		apiKey:          apiKey,
		inProgressFQDNs: make(map[string]inProgressInfo),
		client:          &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl := acme.DNS01Record(domain, keyAuth)
	if ttl < 300 {
		ttl = 300 // 300 is gandi minimum value for ttl
	}

	// find authZone
	authZone, err := findZoneByFqdn(fqdn, acme.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("Gandi DNS: findZoneByFqdn failure: %v", err)
	}

	// determine name of TXT record
	if !strings.HasSuffix(
		strings.ToLower(fqdn), strings.ToLower("."+authZone)) {
		return fmt.Errorf(
			"Gandi DNS: unexpected authZone %s for fqdn %s", authZone, fqdn)
	}
	name := fqdn[:len(fqdn)-len("."+authZone)]

	// acquire lock and check there is not a challenge already in
	// progress for this value of authZone
	d.inProgressMu.Lock()
	defer d.inProgressMu.Unlock()

	// add TXT record into authZone
	err = d.addTXTRecord(acme.UnFqdn(authZone), name, value, ttl)
	if err != nil {
		return err
	}

	// save data necessary for CleanUp
	d.inProgressFQDNs[fqdn] = inProgressInfo{
		authZone:  authZone,
		fieldName: name,
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _ := acme.DNS01Record(domain, keyAuth)

	// acquire lock and retrieve authZone
	d.inProgressMu.Lock()
	defer d.inProgressMu.Unlock()
	if _, ok := d.inProgressFQDNs[fqdn]; !ok {
		// if there is no cleanup information then just return
		return nil
	}

	fieldName := d.inProgressFQDNs[fqdn].fieldName
	authZone := d.inProgressFQDNs[fqdn].authZone
	delete(d.inProgressFQDNs, fqdn)

	// delete TXT record from authZone
	return d.deleteTXTRecord(acme.UnFqdn(authZone), fieldName)
}

// Timeout returns the values (20*time.Minute, 20*time.Second) which
// are used by the acme package as timeout and check interval values
// when checking for DNS record propagation with Gandi.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 20 * time.Minute, 20 * time.Second
}

// types for JSON method calls and parameters

type addFieldRequest struct {
	RRSetTTL    int      `json:"rrset_ttl"`
	RRSetValues []string `json:"rrset_values"`
}

type deleteFieldRequest struct {
	Delete bool `json:"delete"`
}

// types for JSON responses

type responseStruct struct {
	Message string `json:"message"`
}

// POSTing/Marshalling/Unmarshalling

func (d *DNSProvider) sendRequest(method string, resource string, payload interface{}) (*responseStruct, error) {
	url := fmt.Sprintf("%s/%s", endpoint, resource)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if len(d.apiKey) > 0 {
		req.Header.Set("X-Api-Key", d.apiKey)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Gandi DNS: request failed with HTTP status code %d", resp.StatusCode)
	}
	var response responseStruct
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil && method != http.MethodDelete {
		return nil, err
	}

	return &response, nil
}

// functions to perform API actions

func (d *DNSProvider) addTXTRecord(domain string, name string, value string, ttl int) error {
	target := fmt.Sprintf("domains/%s/records/%s/TXT", domain, name)
	response, err := d.sendRequest(http.MethodPut, target, addFieldRequest{
		RRSetTTL:    ttl,
		RRSetValues: []string{value},
	})
	if response != nil {
		log.Infof("Gandi DNS: %s", response.Message)
	}
	return err
}

func (d *DNSProvider) deleteTXTRecord(domain string, name string) error {
	target := fmt.Sprintf("domains/%s/records/%s/TXT", domain, name)
	response, err := d.sendRequest(http.MethodDelete, target, deleteFieldRequest{
		Delete: true,
	})
	if response != nil && response.Message == "" {
		log.Infof("Gandi DNS: Zone record deleted")
	}
	return err
}
