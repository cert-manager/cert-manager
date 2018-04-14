package dnsimple

import (
	"fmt"
	"os"
	"strconv"

	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dnsimpleZoneClient *dnsimple.ZonesService
	dnsimpleAccountID  string
}

func NewDNSProvider() (*DNSProvider, error) {
	oauthToken := getOauthToken()
	return NewDNSProviderCredentials(oauthToken)
}

func NewDNSProviderCredentials(oauthToken string) (*DNSProvider, error) {
	if oauthToken == "" {
		return nil, fmt.Errorf("DNSimple OAuth token missing")
	}

	client := dnsimple.NewClient(dnsimple.NewOauthTokenCredentials(oauthToken))

	whoamiResponse, err := client.Identity.Whoami()
	if err != nil {
		return nil, fmt.Errorf("DNSimple Whoami() returned error: %v", err)
	}

	accountID := strconv.Itoa(whoamiResponse.Data.Account.ID)

	return &DNSProvider{
		dnsimpleZoneClient: client.Zones,
		dnsimpleAccountID:  accountID,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl := util.DNS01Record(domain, keyAuth)

	return c.createRecord(fqdn, value, ttl)
}

func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _ := util.DNS01Record(domain, keyAuth)

	return c.removeRecord(fqdn)
}

func getOauthToken() string {
	return os.Getenv("DNSIMPLE_OAUTH_TOKEN")
}

func (c *DNSProvider) createRecord(fqdn, value string, ttl int) error {
	zone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)

	if err != nil {
		return err
	}
	zoneID := util.UnFqdn(zone)

	newZoneRecord := dnsimple.ZoneRecord{
		Name:    util.UnFqdn(fqdn),
		Content: value,
		Type:    "TXT",
		TTL:     ttl,
	}
	_, err = c.dnsimpleZoneClient.CreateRecord(c.dnsimpleAccountID, zoneID, newZoneRecord)

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
	recordID, err := c.getRecordID(zoneID, util.UnFqdn(fqdn))
	if err != nil {
		return err
	}

	_, err = c.dnsimpleZoneClient.DeleteRecord(c.dnsimpleAccountID, zoneID, recordID)
	if err != nil {
		return err
	}

	return nil
}

func (c *DNSProvider) getRecordID(zoneID, recordName string) (recordID int, err error) {
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

	return 0, fmt.Errorf("No record id found")
}
