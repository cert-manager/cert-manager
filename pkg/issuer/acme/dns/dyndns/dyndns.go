// Package azuredns implements a DNS provider for solving the DNS-01 challenge
// using Azure DNS.
package dyndns

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"github.com/nesv/go-dynect/dynect"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/golang/glog"
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	client      *dynect.Client
	zoneName          string
}

// ZonePublishRequest is missing from dynect but the notes field is a nice place to let
// external-dns report some internal info during commit
type ZonePublishRequest struct {
	Publish bool   `json:"publish"`
	Notes   string `json:"notes"`
}

type ZonePublishResponse struct {
	dynect.ResponseBlock
	Data map[string]interface{} `json:"data"`
}

// NewDNSProvider returns a DNSProvider instance configured for the Azure
// DNS service.
// Credentials are automatically detected from environment variables
func NewDNSProvider() (*DNSProvider, error) {
	glog.Flush()

	dynCustomerName := os.Getenv("DYN_CUSTOMER_NAME")
	dynUsername     := os.Getenv("DYN_USERNAME")
	dynPassword     := os.Getenv("DYN_PASSWORD")
	dynZoneName     := os.Getenv("DYN_ZONE_NAME")

	return NewDynDNSProvider(dynCustomerName, dynUsername, dynPassword, dynZoneName)
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Azure
// DNS service using static credentials from its parameters
func NewDynDNSProvider(dynCustomerName, dynUsername, dynPassword, dynZoneName string) (*DNSProvider, error) {
	glog.V(4).Infof("creating a new dyndns provider")
	client := dynect.NewClient(dynCustomerName)
	var resp dynect.LoginResponse
	var req = dynect.LoginBlock{
		Username:     dynUsername,
		Password:     dynPassword,
		CustomerName: dynCustomerName}


	errSession := client.Do("POST", "Session", req, &resp)
	if errSession != nil {
		log.Fatalf("Problem creating a session error: %s", errSession)
	} else {
		glog.Infof("Successfully created Dyn session")
	}
	client.Token = resp.Data.Token

	return &DNSProvider{
		client:      client,
		zoneName:    dynZoneName,
	}, nil
}

func errorOrValue(err error, value interface{}) interface{} {
	if err == nil {
		return value
	}

	return err
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	glog.V(4).Infof("creating a new dyndns record: %s, token: %s, keyAuth: %s\n", domain, token, keyAuth)
	fqdn, value, ttl := util.DNS01Record(domain, keyAuth)

	return c.createRecord(fqdn, value, ttl)
}

func (c *DNSProvider) createRecord(fqdn, value string, ttl int) error {
	link := fmt.Sprintf("%sRecord/%s/%s/", "TXT", c.zoneName, fqdn)
	glog.V(4).Infof("the link is: %s", link)

	recordData := dynect.DataBlock{}
	recordData.TxtData = value
	record := dynect.RecordRequest{
		TTL:   "60",
		RData: recordData,
	}

	response := dynect.RecordResponse{}
	err := c.client.Do("POST", link, record, &response)
	glog.Infof("Creating record %s: %+v,", link, errorOrValue(err, &response))
	if err != nil {
		log.Fatalf("Error creating record: %s, %v", fqdn, err)
		return err
	}
	glog.Infof("Commmiting changes")
	commit(c)

	glog.V(4).Info("sleeping for 1.3 seconds")
	time.Sleep(1300 * time.Millisecond)

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	glog.Infof("creating a new dyndns record: %s, token: %s, keyAuth: %s\n", domain, token, keyAuth)
	fqdn, _, _ := util.DNS01Record(domain, keyAuth)
	link := fmt.Sprintf("%sRecord/%s/%s/", "TXT", c.zoneName, fqdn)
	glog.Infof("deleting record: %s", link)
	response := dynect.RecordResponse{}
	err := c.client.Do("DELETE", link, nil, &response)
	glog.Infof("Deleting record %s: %+v\n", link, errorOrValue(err, &response))
	if err != nil {
		log.Fatalf("Error getting deleting domain name: %s, %v", domain, err)
		return err
	}
	glog.Infof("Commmiting changes")
	commit(c)
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}


func (c *DNSProvider) getHostedZoneName(fqdn string) (string, error) {
	if c.zoneName != "" {
		return c.zoneName, nil
	}
	z, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return "", err
	}

	if len(z) == 0 {
		return "", fmt.Errorf("Zone %s not found for domain %s", z, fqdn)
	}

	return util.UnFqdn(z), nil
}

func (c *DNSProvider) trimFqdn(fqdn string) string {
	return strings.TrimSuffix(strings.TrimSuffix(fqdn, "."), "."+c.zoneName)
}

// commit commits all pending changes. It will always attempt to commit, if there are no
func commit(c *DNSProvider) error {
	// extra call if in debug mode to fetch pending changes
	h, err := os.Hostname()
	if err != nil {
		h = "unknown-host"
	}
	notes := fmt.Sprintf("Change by external-dns@%s, DynAPI@%s, %s on %s",
		"external-dns-client",
		"external-dns-client-version",
		time.Now().Format(time.RFC3339),
		h,
	)

	zonePublish := ZonePublishRequest{
		Publish: true,
		Notes:   notes,
	}

	response := ZonePublishResponse{}
	glog.Infof("Commiting changes for zone %s: %+v", c.zoneName, errorOrValue(err, &response))
	err = c.client.Do("PUT", fmt.Sprintf("Zone/%s/", c.zoneName), &zonePublish, &response)
	if err != nil {
		log.Fatal("Error committing changes to zone, error: ", err)
	} else {
		glog.Info(response)
	}

	return nil
}
