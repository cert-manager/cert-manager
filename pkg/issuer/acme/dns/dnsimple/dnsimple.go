/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package dnsimple

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"golang.org/x/oauth2"
)

const (
	dnsimpleSandboxBaseURL   = "https://api.sandbox.dnsimple.com"
	dnsimpleNoRecordErrorMsg = "No record id found"
)

func getOauthToken() string {
	return os.Getenv("DNSIMPLE_OAUTH_TOKEN")
}

func isDNSimpleSandbox() bool {
	return os.Getenv("DNSIMPLE_SANDBOX") != ""
}

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers   []string
	dnsimpleZoneClient *dnsimple.ZonesService
	dnsimpleAccountID  string
}

func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	oauthToken := getOauthToken()
	return NewDNSProviderCredentials(oauthToken, dns01Nameservers)
}

func NewDNSProviderCredentials(oauthToken string, dns01Nameservers []string) (*DNSProvider, error) {
	if oauthToken == "" {
		return nil, fmt.Errorf("DNSimple OAuth token is missing")
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: oauthToken})
	tc := oauth2.NewClient(context.Background(), ts)

	client := dnsimple.NewClient(tc)
	client.UserAgent = "cert-manager"

	if isDNSimpleSandbox() {
		client.BaseURL = dnsimpleSandboxBaseURL
	}

	whoamiResponse, err := client.Identity.Whoami()
	if err != nil {
		return nil, fmt.Errorf("DNSimple Whoami() returned error: %v", err)
	}

	if whoamiResponse.Data.Account == nil {
		return nil, fmt.Errorf("DNSimple user tokens are not supported, please use an account token")
	}

	accountID := strconv.FormatInt(whoamiResponse.Data.Account.ID, 10)

	return &DNSProvider{
		dnsimpleZoneClient: client.Zones,
		dnsimpleAccountID:  accountID,
		dns01Nameservers:   dns01Nameservers,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl, err := util.DNS01Record(domain, keyAuth, c.dns01Nameservers)

	if err != nil {
		return err
	}

	return c.createRecord(fqdn, value, ttl)
}

func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _, err := util.DNS01Record(domain, keyAuth, c.dns01Nameservers)
	if err != nil {
		return err
	}

	return c.removeRecord(fqdn)
}

func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

func (c *DNSProvider) createRecord(fqdn, value string, ttl int) error {
	zone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return err
	}

	zoneID := util.UnFqdn(zone)

	verifiedZoneID, err := c.getZoneID(zoneID)
	if err != nil {
		return err
	}

	recordName := c.extractRecordName(fqdn, zoneID)
	recordID, err := c.getRecordID(verifiedZoneID, recordName)
	// Do not attempt to create an existing record
	if recordID != 0 {
		return nil
	}

	newZoneRecord := dnsimple.ZoneRecord{
		Name:    recordName,
		Content: value,
		Type:    "TXT",
		TTL:     ttl,
	}
	_, err = c.dnsimpleZoneClient.CreateRecord(c.dnsimpleAccountID, verifiedZoneID, newZoneRecord)

	if err != nil {
		return err
	}

	return nil
}

func (c *DNSProvider) removeRecord(fqdn string) error {
	zone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return err
	}

	zoneID := util.UnFqdn(zone)

	verifiedZoneID, err := c.getZoneID(zoneID)
	if err != nil {
		return err
	}

	recordName := c.extractRecordName(fqdn, zoneID)
	recordID, err := c.getRecordID(verifiedZoneID, recordName)
	if err != nil {
		// Do not attempt to delete a non-existing record
		if err.Error() == dnsimpleNoRecordErrorMsg {
			return nil
		}

		return err
	}

	_, err = c.dnsimpleZoneClient.DeleteRecord(c.dnsimpleAccountID, verifiedZoneID, recordID)
	if err != nil {
		return err
	}

	return nil
}

func (c *DNSProvider) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

func (c *DNSProvider) getZoneID(localZoneName string) (zoneName string, err error) {
	zoneResponse, err := c.dnsimpleZoneClient.GetZone(c.dnsimpleAccountID, localZoneName)
	if err != nil {
		return "", err
	}

	if zoneResponse.Data.ID == 0 {
		return "", fmt.Errorf("No zone found in DNSimple for zone %s", localZoneName)
	}

	if zoneResponse.Data.Name != localZoneName {
		return "", fmt.Errorf("Incorrect zone %s returned in lookup for %s", zoneResponse.Data.Name, localZoneName)
	}

	return zoneResponse.Data.Name, nil
}

func (c *DNSProvider) getRecordID(zoneID, recordName string) (recordID int64, err error) {
	page := 1
	listOptions := &dnsimple.ZoneRecordListOptions{Name: recordName, Type: "TXT"}
	for {
		listOptions.Page = page
		records, err := c.dnsimpleZoneClient.ListRecords(c.dnsimpleAccountID, zoneID, listOptions)
		if err != nil {
			return 0, err
		}

		for _, record := range records.Data {
			if record.Name == recordName {
				return record.ID, nil
			}
		}

		page++
		if page > records.Pagination.TotalPages {
			break
		}
	}

	return 0, fmt.Errorf(dnsimpleNoRecordErrorMsg)
}
