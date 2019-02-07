/*
Copyright 2019 The Jetstack cert-manager contributors.

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

// Package akamai implements a DNS provider for solving the DNS-01
// challenge using Akamai FastDNS.
// See https://developer.akamai.com/api/luna/config-dns/overview.html
package akamai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang/glog"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	pkgutil "github.com/jetstack/cert-manager/pkg/util"
	"github.com/pkg/errors"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	// serviceConsumerDomain as issued by Akamai Luna Control Center.
	// The ServiceConsumerDomain is the base URL.
	serviceConsumerDomain string

	auth *EdgeGridAuth

	transport              http.RoundTripper
	findHostedDomainByFqdn func(string, []string) (string, error)
}

// NewDNSProvider returns a DNSProvider instance configured for Akamai.
func NewDNSProvider(serviceConsumerDomain, clientToken, clientSecret, accessToken string, dns01Nameservers []string) (*DNSProvider, error) {
	return &DNSProvider{
		dns01Nameservers,
		serviceConsumerDomain,
		NewEdgeGridAuth(clientToken, clientSecret, accessToken),
		http.DefaultTransport,
		findHostedDomainByFqdn,
	}, nil
}

func findHostedDomainByFqdn(fqdn string, ns []string) (string, error) {
	zone, err := util.FindZoneByFqdn(fqdn, ns)
	if err != nil {
		return "", err
	}

	return util.UnFqdn(zone), nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (a *DNSProvider) Present(domain, fqdn, value string) error {
	return a.addTxtRecord(fqdn, &dns01Record{value, 60})
}

// CleanUp removes the TXT record matching the specified parameters
func (a *DNSProvider) CleanUp(domain, fqdn, value string) error {
	return a.removeTxtRecord(fqdn, value)
}

type dns01Record struct {
	value string
	ttl   int
}

func (a *DNSProvider) addTxtRecord(fqdn string, dns01Record *dns01Record) error {
	zoneData, hostedDomain, err := a.findAndLoadZone(fqdn)
	if err != nil {
		return err
	}

	recordName, err := makeTxtRecordName(fqdn, hostedDomain)
	if err != nil {
		return errors.Wrapf(err, "failed to create TXT record name")
	}

	updated, err := zoneData.setTxtRecord(recordName, dns01Record)
	if err != nil {
		return errors.Wrapf(err, "failed to set TXT record in %q", hostedDomain)
	}
	if !updated {
		// don't bother talking to akamai if we don't need to add the zone
		return nil
	}

	return a.updateZone(hostedDomain, zoneData)
}

func (a *DNSProvider) removeTxtRecord(fqdn string, value string) error {
	zoneData, hostedDomain, err := a.findAndLoadZone(fqdn)
	if err != nil {
		return err
	}

	recordName, err := makeTxtRecordName(fqdn, hostedDomain)
	if err != nil {
		return errors.Wrapf(err, "failed to create TXT record name")
	}

	updated, err := zoneData.removeTxtRecord(recordName, value)
	if err != nil {
		return errors.Wrapf(err, "failed to remove TXT record in %q", hostedDomain)
	}
	if !updated {
		// don't bother talking to akamai if we don't need to remove the zone
		return nil
	}

	return a.updateZone(hostedDomain, zoneData)
}

func (a *DNSProvider) findAndLoadZone(fqdn string) (zoneData, string, error) {
	hostedDomain, err := a.findHostedDomainByFqdn(fqdn, a.dns01Nameservers)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to determine hosted domain for %q", fqdn)
	}

	zoneData, err := a.loadZoneData(hostedDomain)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to load zone data for %q", hostedDomain)
	}
	return zoneData, hostedDomain, nil
}

func (a *DNSProvider) updateZone(hostedDomain string, zonedata zoneData) error {
	newSerial, err := zonedata.incSoaSerial()
	if err != nil {
		return errors.Wrapf(err, "failed to increment SOA serial for %q", hostedDomain)
	}

	if err := a.saveZoneData(hostedDomain, zonedata); err != nil {
		return errors.Wrapf(err, "failed to save zone data for %q", hostedDomain)
	}

	glog.V(4).Infof("Updated Akamai TXT record on %q using SOA serial of %d", hostedDomain, newSerial)
	return nil
}

func makeTxtRecordName(fqdn, hostedDomain string) (string, error) {
	if !strings.HasSuffix(fqdn, "."+hostedDomain+".") {
		return "", errors.Errorf("fqdn %q is not part of %q", fqdn, hostedDomain)
	}

	return fqdn[0 : len(fqdn)-len(hostedDomain)-2], nil
}

func (a *DNSProvider) urlForDomain(domain string) string {
	return fmt.Sprintf("https://%s/config-dns/v1/zones/%s", a.serviceConsumerDomain, domain)
}

func (a *DNSProvider) loadZoneData(domain string) (zoneData, error) {
	url := a.urlForDomain(domain)
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create HTTP request")
	}

	responsePayload, err := a.makeRequest(req)
	if err != nil {
		return nil, err
	}

	var zoneData map[string]interface{}
	err = json.NewDecoder(bytes.NewReader(responsePayload)).Decode(&zoneData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode Akamai OPEN API response")
	}

	return zoneData, nil
}

func (a *DNSProvider) saveZoneData(domain string, data zoneData) error {
	body, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "failed to encode zone data")
	}

	url := a.urlForDomain(domain)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "failed to create HTTP request")
	}

	req.Header.Set("Content-Type", "application/json")

	if _, err := a.makeRequest(req); err != nil {
		return err
	}

	return nil
}

func (a *DNSProvider) makeRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("User-Agent", pkgutil.CertManagerUserAgent)

	if err := a.auth.SignRequest(req); err != nil {
		return nil, errors.Wrap(err, "failed to sign HTTP request")
	}

	client := http.Client{
		Transport: a.transport,
		Timeout:   30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error querying Akamai OPEN API")
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Akamai OPEN API returned %d %s", resp.StatusCode, resp.Status)
	}

	responsePayload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response payload")
	}

	return responsePayload, nil
}

type zoneData map[string]interface{}

func (z zoneData) setTxtRecord(name string, dns01Record *dns01Record) (bool, error) {
	txtRecords, err := z.getTxts()
	if err != nil {
		return false, err
	}
	index, err := findRecordIndex(txtRecords, name, dns01Record.value)
	if err != nil {
		return false, err
	}
	if index != -1 {
		// we already have this txt record
		return false, nil
	}

	txtRecords = append(txtRecords, map[string]interface{}{
		"name":   name,
		"ttl":    dns01Record.ttl,
		"active": true,
		"target": dns01Record.value,
	})

	return true, z.setTxts(txtRecords)
}

func (z zoneData) removeTxtRecord(recordname string, value string) (bool, error) {
	txtRecords, err := z.getTxts()
	if err != nil {
		return false, err
	}
	index, err := findRecordIndex(txtRecords, recordname, value)
	if err != nil {
		return false, err
	}
	if index == -1 {
		// nothing to do
		return false, nil
	}
	newTxts := make([]interface{}, 0, len(txtRecords)-1)
	for i := 0; i < len(txtRecords); i++ {
		if index != i {
			newTxts = append(newTxts, txtRecords[i])
		}
	}
	err = z.setTxts(newTxts)
	if err != nil {
		return false, err
	}
	return true, nil
}

func findRecordIndex(txtRecords []interface{}, recordname string, value string) (int, error) {
	for i, txtRaw := range txtRecords {
		txt, ok := txtRaw.(map[string]interface{})
		if !ok {
			return -1, errors.New("malformed TXT record from Akamai API")
		}
		name, ok := txt["name"].(string)
		if !ok {
			return -1, errors.New("malformed TXT record from Akamai API")
		}
		if name != recordname {
			continue
		}
		v, ok := txt["target"].(string)
		if !ok {
			return -1, errors.New("malformed TXT record from Akamai API")
		}
		if v == value {
			return i, nil
		}
	}
	return -1, nil
}

func (z zoneData) getTxts() ([]interface{}, error) {
	zone, ok := z["zone"].(map[string]interface{})
	if !ok {
		return nil, errors.New("failed to retrieve zone from zone data")
	}

	var txtRecords []interface{}
	if txtNode, ok := zone["txt"]; ok {
		if txtRecords, ok = txtNode.([]interface{}); !ok {
			return nil, errors.New("failed to retrieve TXT records from zone data")
		}
		return txtRecords, nil
	}
	return nil, nil
}

func (z zoneData) setTxts(txtRecs []interface{}) error {
	zone, ok := z["zone"].(map[string]interface{})
	if !ok {
		return errors.New("failed to set zone data on zone")
	}
	if len(txtRecs) > 0 {
		zone["txt"] = txtRecs
	} else {
		delete(zone, "txt")
	}
	return nil
}

func (z zoneData) incSoaSerial() (uint64, error) {
	soa, ok := z["zone"].(map[string]interface{})["soa"].(map[string]interface{})
	if !ok {
		return 0, errors.New("failed to retrieve SOA record from zone data")
	}

	serial, ok := soa["serial"].(float64)
	if !ok {
		return 0, errors.New("failed to retrieve SOA serial from zone data")
	}

	newSerial := uint64(serial) + 1
	soa["serial"] = newSerial
	return newSerial, nil
}

func deleteRecord(records []interface{}, name string) []interface{} {
	for pos := range records {
		if recordName, ok := records[pos].(map[string]interface{})["name"]; ok && recordName == name {
			return append(records[:pos], records[pos+1:]...)
		}
	}

	return nil
}

func updateRecord(records []interface{}, name string, record map[string]interface{}) []interface{} {
	for pos := range records {
		if records[pos].(map[string]interface{})["name"] == name {
			records[pos] = record
			return records
		}
	}

	return append(records, record)
}
