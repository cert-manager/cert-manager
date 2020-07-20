package designate

import (
	"fmt"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/recordsets"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/zones"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	recordType         = "TXT"
	recordTTL          = 1800
	defaultDescription = "ACME DNS challenge record"
	zoneStatusActive   = "ACTIVE"
	pollTimeout        = 2 * time.Minute
	pollInterval       = 5 * time.Second
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	client      *gophercloud.ServiceClient
	zoneID      string
	moreHeaders map[string]string
}

func NewDNSProvider() (*DNSProvider, error) {
	return newProviderFromAuth(
		NewAuthFromENV(),
	)
}

func NewDNSProviderCredentials(authURL, regionName, userName, userDomainName, password, projectName, projectDomainName, zoneName string) (*DNSProvider, error) {
	return newProviderFromAuth(
		&Auth{
			authURL:           authURL,
			regionName:        regionName,
			userName:          userName,
			userDomainName:    userDomainName,
			password:          password,
			projectName:       projectName,
			projectDomainName: projectDomainName,
			zoneName:          zoneName,
		},
	)
}

func newProviderFromAuth(auth *Auth) (*DNSProvider, error) {
	providerClient, err := NewAuthenticatedProviderClient(auth)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate provider client")
	}

	client, err := openstack.NewDNSV2(
		providerClient,
		gophercloud.EndpointOpts{},
	)
	if err != nil {
		return nil, errors.Wrap(err, "openstack authentication failed")
	}

	provider := &DNSProvider{
		client: client,
		moreHeaders: map[string]string{
			"X-Auth-All-Projects": "true",
		},
	}

	provider.zoneID, err = provider.findZoneIDByName(util.ToFqdn(auth.zoneName))
	return provider, err
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (p *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return pollTimeout, pollInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge
func (p *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, err := util.DNS01LookupFQDN(domain, false)
	if err != nil {
		return err
	}

	url := p.client.ServiceURL("zones", p.zoneID, "recordsets")
	opts := gophercloud.RequestOpts{
		OkCodes:     []int{201, 202},
		MoreHeaders: p.moreHeaders,
	}

	name := util.ToFqdn(fqdn)
	rec, err := recordsets.CreateOpts{
		Name:        name,
		TTL:         recordTTL,
		Type:        recordType,
		Description: defaultDescription,
		Records:     []string{keyAuth},
	}.ToRecordSetCreateMap()
	if err != nil {
		return err
	}

	var res gophercloud.Result
	if _, res.Err = p.client.Post(url, &rec, &res.Body, &opts); res.Err != nil {
		return errors.Wrapf(res.Err, "could not create recordset name: %s, type: %s, records: %v, ttl: %v in zone uid %s", name, recordType, value, recordTTL, p.zoneID)
	}

	err = p.waitUntilDesignateZoneIsUpdatedOrTimeout()
	return err
}

// CleanUp removes the TXT record matching the specified parameters
func (p *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, err := util.DNS01LookupFQDN(domain, false)
	if err != nil {
		return err
	}

	record, err := p.findTxtRecord(fqdn)
	if err != nil {
		return err
	}

	url := p.client.ServiceURL("zones", p.zoneID, "recordsets", record.ID)
	opts := gophercloud.RequestOpts{
		OkCodes:     []int{202},
		MoreHeaders: p.moreHeaders,
	}

	var res gophercloud.Result
	if _, res.Err = p.client.Delete(url, &opts); res.Err != nil {
		return errors.Wrapf(res.Err, "could not delete recordset %s with uid %v in zone uid %v", fqdn, record.ID, p.zoneID)
	}

	err = p.waitUntilDesignateZoneIsUpdatedOrTimeout()
	return err
}

func (p *DNSProvider) findTxtRecord(fqdn string) (recordsets.RecordSet, error) {
	recs, err := p.listDesignateRecordsetsForZone(p.zoneID, fqdn)
	if err != nil {
		return recordsets.RecordSet{}, err
	}

	switch l := len(recs); {
	case l == 1:
		return recs[0], nil
	case l > 1:
		return recordsets.RecordSet{}, fmt.Errorf("found multiple recordsets for %s in zone %s", fqdn, p.zoneID)
	default:
		return recordsets.RecordSet{}, fmt.Errorf("no record found for %s", fqdn)
	}
}

func (p *DNSProvider) findZoneIDByName(zoneName string) (string, error) {
	zoneList, err := p.listDesignateZones(zones.ListOpts{Name: util.ToFqdn(zoneName)})
	if err != nil {
		return "", err
	}

	switch l := len(zoneList); {
	case l == 1:
		return zoneList[0].ID, nil
	case l > 1:
		return "", errors.Errorf("Multiple zones with name '%s' found", zoneName)
	default:
		return "", errors.Errorf("No zone with name '%s' found", zoneName)
	}
}

func (p *DNSProvider) listDesignateZones(listOpts zones.ListOpts) (zoneList []zones.Zone, err error) {
	url := p.client.ServiceURL("zones")
	listOptsString, err := listOpts.ToZoneListQuery()
	if err != nil {
		return nil, err
	}
	url += listOptsString

	opts := gophercloud.RequestOpts{
		MoreHeaders: p.moreHeaders,
	}

	var (
		res     gophercloud.Result
		resData struct {
			Zones []zones.Zone `json:"zones"`
		}
	)

	_, res.Err = p.client.Get(url, &res.Body, &opts)
	if err := res.ExtractInto(&resData); err != nil {
		return nil, errors.Wrapf(err, "failed to list zones from %v, options: %#v", url, opts)
	}

	return resData.Zones, nil
}

func (p *DNSProvider) listDesignateRecordsetsForZone(zoneID, recordsetName string) (recordsetList []recordsets.RecordSet, err error) {
	opts := recordsets.ListOpts{}
	if recordsetName != "" {
		opts.Name = util.ToFqdn(recordsetName)
	}

	pager := recordsets.ListByZone(p.client, zoneID, opts)
	pager.Headers = mergeMaps(p.moreHeaders, pager.Headers)

	pages := 0
	err = pager.EachPage(func(page pagination.Page) (bool, error) {
		pages++
		r, err := recordsets.ExtractRecordSets(page)
		if err != nil {
			return false, err
		}
		recordsetList = r
		return true, nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list recordsets in zone %s", zoneID)
	}

	return recordsetList, nil
}

func (p *DNSProvider) waitUntilDesignateZoneIsUpdatedOrTimeout() error {
	err := wait.PollImmediate(
		pollInterval, pollTimeout,
		func() (done bool, err error) {
			zone, err := p.showDesignateZone(p.zoneID)
			if err != nil {
				return false, err
			}
			return zone.Status == zoneStatusActive, nil
		},
	)
	return err
}

func (p *DNSProvider) showDesignateZone(zoneID string) (zones.Zone, error) {
	url := p.client.ServiceURL("zones", zoneID)
	opts := gophercloud.RequestOpts{
		MoreHeaders: p.moreHeaders,
	}

	var (
		res  gophercloud.Result
		zone zones.Zone
	)
	_, res.Err = p.client.Get(url, &res.Body, &opts)
	if err := res.ExtractInto(zone); err != nil {
		return zones.Zone{}, errors.Wrapf(err, "failed to show zone with uid %s", zoneID)
	}
	return zone, nil
}
