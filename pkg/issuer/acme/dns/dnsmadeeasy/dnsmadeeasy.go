package dnsmadeeasy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

const DefaultBaseURL = "https://api.dnsmadeeasy.com/V2.0"

// DNSProvider is an implementation of the acme.ChallengeProvider interface that uses
// DNSMadeEasy's DNS API to manage TXT records for a domain.
type DNSProvider struct {
	baseURL          string
	apiKey           string
	secretKey        string
	domainID         uint
	dns01Nameservers []string
	client           *http.Client
}

// Domain holds the DNSMadeEasy API representation of a Domain
type Domain struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// Record holds the DNSMadeEasy API representation of a Domain Record
type Record struct {
	ID       uint   `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	TTL      uint   `json:"ttl"`
	SourceID uint   `json:"sourceId"`
}

// NewDNSProvider uses the supplied credentials to return a
// DNSProvider instance configured for DNSMadeEasy.
func NewDNSProvider(baseURL, apiKey, secretKey string, domainID uint, dns01Nameservers []string) (*DNSProvider, error) {
	glog.Errorf("NewDNSProvider: dns01Nameservers: %v", dns01Nameservers)
	if apiKey == "" || secretKey == "" {
		return nil, fmt.Errorf("DNS Made Easy credentials missing")
	}

	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
	}

	return &DNSProvider{
		baseURL:          baseURL,
		apiKey:           apiKey,
		secretKey:        secretKey,
		domainID:         domainID,
		dns01Nameservers: dns01Nameservers,
		client:           client,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (d *DNSProvider) Present(domainName, token, keyAuth string) error {
	glog.Errorf("d.dns01Nameservers: %v", d.dns01Nameservers)
	fqdn, value, ttl, err := util.DNS01Record(domainName, keyAuth, d.dns01Nameservers)
	if err != nil {
		return err
	}

	authZone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return err
	}

	// fetch the domain details
	domain, err := d.getDomain(authZone)
	if err != nil {
		return err
	}

	// validate against domainID
	if d.domainID > 0 && d.domainID != uint(domain.ID) {
		return fmt.Errorf("DNS Made Easy domain ID %d is not authoritative for %s", d.domainID, authZone)
	}

	// find existing records, as there is no update-or-create
	name := strings.Replace(fqdn, "."+authZone, "", 1)
	records, err := d.getRecords(domain, name, "TXT")
	if err != nil {
		return err
	}

	// check for existing correct record
	for _, record := range *records {
		if record.Value == value {
			return nil
		}
	}

	// create new record
	record := &Record{Type: "TXT", Name: name, Value: value, TTL: uint(ttl)}
	err = d.createRecord(domain, record)
	return err
}

// CleanUp removes the TXT records matching the specified parameters
func (d *DNSProvider) CleanUp(domainName, token, keyAuth string) error {
	fqdn, _, _, err := util.DNS01Record(domainName, keyAuth, d.dns01Nameservers)
	if err != nil {
		return err
	}

	authZone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return err
	}

	// fetch the domain details
	domain, err := d.getDomain(authZone)
	if err != nil {
		return err
	}

	// validate against domainID
	if d.domainID > 0 && d.domainID != domain.ID {
		return fmt.Errorf("DNS Made Easy domain ID %n is not authoritative for %s", d.domainID, authZone)
	}

	// find matching records
	name := strings.Replace(fqdn, "."+authZone, "", 1)
	records, err := d.getRecords(domain, name, "TXT")
	if err != nil {
		return err
	}

	// delete records
	for _, record := range *records {
		err = d.deleteRecord(record)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

func (d *DNSProvider) getDomain(authZone string) (*Domain, error) {
	domainName := authZone[0 : len(authZone)-1]
	resource := fmt.Sprintf("%s%s", "/dns/managed/name?domainname=", domainName)

	resp, err := d.sendRequest(http.MethodGet, resource, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	domain := &Domain{}
	err = json.NewDecoder(resp.Body).Decode(&domain)
	if err != nil {
		return nil, err
	}

	return domain, nil
}

func (d *DNSProvider) getRecords(domain *Domain, recordName, recordType string) (*[]Record, error) {
	resource := fmt.Sprintf("%s/%d/%s%s%s%s", "/dns/managed", domain.ID, "records?recordName=", recordName, "&type=", recordType)

	resp, err := d.sendRequest(http.MethodGet, resource, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	type recordsResponse struct {
		Records *[]Record `json:"data"`
	}

	records := &recordsResponse{}
	err = json.NewDecoder(resp.Body).Decode(&records)
	if err != nil {
		return nil, err
	}

	return records.Records, nil
}

func (d *DNSProvider) createRecord(domain *Domain, record *Record) error {
	url := fmt.Sprintf("%s/%d/%s", "/dns/managed", domain.ID, "records")

	resp, err := d.sendRequest(http.MethodPost, url, record)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (d *DNSProvider) deleteRecord(record Record) error {
	resource := fmt.Sprintf("%s/%d/%s/%d", "/dns/managed", record.SourceID, "records", record.ID)

	resp, err := d.sendRequest(http.MethodDelete, resource, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (d *DNSProvider) sendRequest(method, resource string, payload interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", d.baseURL, resource)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().UTC().Format(time.RFC1123)
	signature := computeHMAC(timestamp, d.secretKey)

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-dnsme-apiKey", d.apiKey)
	req.Header.Set("x-dnsme-requestDate", timestamp)
	req.Header.Set("x-dnsme-hmac", signature)
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("DNSMadeEasy API request failed with HTTP status code %d", resp.StatusCode)
	}

	return resp, nil
}

func computeHMAC(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
