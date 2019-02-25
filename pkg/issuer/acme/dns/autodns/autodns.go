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

package autodns

import (
	"github.com/actano/autodns-api-go/pkg/client"
	"github.com/actano/autodns-api-go/pkg/zone"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

type DNSProvider struct {
	dns01Nameservers []string
	client           *client.AutoDnsClient
}

func NewDNSProvider(username, password, context string, dns01Nameservers []string) *DNSProvider {
	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		client:           client.NewAutoDnsClient(username, password, context),
	}
}

func (c *DNSProvider) Present(domain, fqdn, value string) error {
	zoneName, err := c.getZone(fqdn)

	if err != nil {
		return err
	}

	resourceRecord := c.getResourceRecord(fqdn, value)

	addRecords := []zone.ResourceRecord{
		resourceRecord,
	}

	err = c.client.Zone.UpdateBulk(zoneName, addRecords, nil)

	return err
}

func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	zoneName, err := c.getZone(fqdn)

	if err != nil {
		return err
	}

	resourceRecord := c.getResourceRecord(fqdn, value)

	removeRecords := []zone.ResourceRecord{
		resourceRecord,
	}

	err = c.client.Zone.UpdateBulk(zoneName, nil, removeRecords)

	return err
}

func (c *DNSProvider) getZone(fqdn string) (string, error) {
	zoneName, err := util.FindZoneByFqdn(fqdn, c.dns01Nameservers)

	if err != nil {
		return "", err
	}

	return util.UnFqdn(zoneName), nil
}

func (c *DNSProvider) getResourceRecord(fqdn, value string) zone.ResourceRecord {
	return zone.ResourceRecord{
		Name:  fqdn,
		Type:  "TXT",
		TTL:   300,
		Value: value,
	}
}
