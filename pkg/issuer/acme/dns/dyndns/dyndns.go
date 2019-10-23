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

// Package dyndns implements a DNS provider for solving the DNS-01 challenge
// using Dyn DNS.
package dyndns

import (
	"fmt"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/nesv/go-dynect/dynect"
	"k8s.io/klog"
	"os"
	"strings"
	"time"
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	client   *dynect.Client
	zoneName string
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

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Dyn.com
// DNS service using static credentials from its parameters
func NewDNSProviderCredentials(dynCustomerName, dynUsername, dynPassword, dynZoneName string) (*DNSProvider, error) {
	klog.V(4).Infof("creating a new dyndns provider")
	client := dynect.NewClient(dynCustomerName)
	var resp dynect.LoginResponse
	var req = dynect.LoginBlock{
		Username:     dynUsername,
		Password:     dynPassword,
		CustomerName: dynCustomerName}

	errSession := client.Do("POST", "Session", req, &resp)
	if errSession != nil {
		klog.Errorf("Problem creating a session error: %s", errSession)
	} else {
		klog.Infof("Successfully created Dyn session")
	}
	client.Token = resp.Data.Token

	return &DNSProvider{
		client:   client,
		zoneName: dynZoneName,
	}, nil
}

func errorOrValue(err error, value interface{}) interface{} {
	if err == nil {
		return value
	}

	return err
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	klog.V(4).Infof("creating a new dyndns record for: %s, fqdn: %s, value: %s\n", domain, fqdn, value)
	fqdnLookup, err := util.DNS01LookupFQDN(domain, false)

	if err != nil {
		return err
	}

	return c.createRecord(fqdnLookup, value, 60)
}

func (c *DNSProvider) createRecord(fqdn, value string, ttl int) error {
	link := fmt.Sprintf("%sRecord/%s/%s/", "TXT", c.zoneName, fqdn)
	klog.V(4).Infof("the link is: %s", link)

	recordData := dynect.DataBlock{}
	recordData.TxtData = value
	record := dynect.RecordRequest{
		TTL:   "60",
		RData: recordData,
	}

	response := dynect.RecordResponse{}
	err := c.client.Do("POST", link, record, &response)
	klog.Infof("Creating record %s: %+v,", link, errorOrValue(err, &response))
	if err != nil {
		klog.Errorf("Error creating record: %s, %v", fqdn, err)
		return err
	}

	commit(c)

	klog.V(4).Info("sleeping for 1.3 seconds")
	time.Sleep(1300 * time.Millisecond)

	return nil
}

func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	klog.Infof("creating a new dyndns record for domain: %s, token: %s, keyAuth: %s\n", domain, token, keyAuth)
	fqdn, err := util.DNS01LookupFQDN(domain, false)

	if err != nil {
		klog.Error("Error while clean up", err)
		return err
	}

	link := fmt.Sprintf("%sRecord/%s/%s/", "TXT", c.zoneName, fqdn)
	klog.Infof("deleting record: %s", link)
	response := dynect.RecordResponse{}
	err = c.client.Do("DELETE", link, nil, &response)
	klog.Infof("Deleting record %s: %+v\n", link, errorOrValue(err, &response))
	if err != nil {
		klog.Errorf("Error deleting domain name: %s, %v", domain, err)
		return err
	}

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
	klog.Infof("Committing changes")
	// extra call if in debug mode to fetch pending changes
	hostName, err := os.Hostname()
	if err != nil {
		hostName = "unknown-host"
	}
	notes := fmt.Sprintf("Change by external-dns@%s, DynAPI@%s, %s on %s",
		"external-dns-client",
		"external-dns-client-version",
		time.Now().Format(time.RFC3339),
		hostName,
	)

	zonePublish := ZonePublishRequest{
		Publish: true,
		Notes:   notes,
	}

	response := ZonePublishResponse{}

	klog.Infof("Committing changes for zone %s: %+v", c.zoneName, errorOrValue(err, &response))

	err = c.client.Do("PUT", fmt.Sprintf("Zone/%s/", c.zoneName), &zonePublish, &response)

	if err != nil {
		klog.Error("Error committing changes to zone, error: ", err)
		return err
	} else {
		klog.Info(response)
	}

	return nil
}
