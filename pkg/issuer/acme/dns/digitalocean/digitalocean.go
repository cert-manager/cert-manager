/*
Copyright 2020 The cert-manager Authors.

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

// Package digitalocean implements a DNS provider for solving the DNS-01
// challenge using digitalocean DNS.
package digitalocean

import (
	"context"
	"errors"
	"os"

	"github.com/digitalocean/godo"
	"golang.org/x/oauth2"

	utiloptions "github.com/cert-manager/cert-manager/internal/options"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           *godo.Client
	resolver         util.Resolver
}

// NewDNSProviderFromOptions constructs an ACME DNS provider for DigitalOcean.
//
// All options are passed via the variadic options parameter.
//
// Required options:
// - Token
// - Nameservers
// - Resolver
func NewDNSProviderFromOptions(ctx context.Context, options ...DNSProviderOption) (*DNSProvider, error) {
	var opt DNSProviderOptions
	for _, o := range options {
		o.ApplyToDNSProviderOptions(&opt)
	}

	err := errors.Join(
		utiloptions.Required(&opt.Token, "DigitalOcean token missing"),
		utiloptions.Required(&opt.Resolver, "resolver is required"),
		utiloptions.NotEmpty(&opt.Nameservers, "nameservers is required"),
	)

	if err != nil {
		return nil, err
	}

	c := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: opt.Token}))

	var clientOpts []godo.ClientOpt

	if opt.UserAgent != "" {
		clientOpts = append(clientOpts, godo.SetUserAgent(opt.UserAgent))
	}

	client, err := godo.New(c, clientOpts...)
	if err != nil {
		return nil, err
	}

	return &DNSProvider{
		dns01Nameservers: opt.Nameservers,
		client:           client,
		resolver:         opt.Resolver,
	}, nil
}

// NewDNSProvider returns a DNSProvider instance configured for digitalocean.
// The access token must be passed in the environment variable DIGITALOCEAN_TOKEN
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProvider(dns01Nameservers []string, userAgent string) (*DNSProvider, error) {
	return NewDNSProviderFromOptions(context.Background(),
		Token(os.Getenv("DIGITALOCEAN_TOKEN")),
		Nameservers(dns01Nameservers),
		UserAgent(userAgent),
		Resolver(util.LegacyCachedResolver()),
	)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for digitalocean.
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProviderCredentials(token string, dns01Nameservers []string, userAgent string) (*DNSProvider, error) {
	return NewDNSProviderFromOptions(context.Background(),
		Token(token),
		Nameservers(dns01Nameservers),
		UserAgent(userAgent),
		Resolver(util.LegacyCachedResolver()),
	)
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(ctx context.Context, _, fqdn, value string) error {
	// if DigitalOcean does not have this zone then we will find out later
	zoneName, err := c.resolver.FindZoneByFQDN(ctx, fqdn, c.dns01Nameservers)
	if err != nil {
		return err
	}

	// check if the record has already been created
	records, err := c.findTxtRecord(ctx, zoneName, fqdn)
	if err != nil {
		return err
	}

	for _, record := range records {
		if record.Type == "TXT" && record.Data == value {
			return nil
		}
	}

	createRequest := &godo.DomainRecordEditRequest{
		Type: "TXT",
		Name: fqdn,
		Data: value,
		TTL:  60,
	}

	_, _, err = c.client.Domains.CreateRecord(
		ctx,
		util.UnFqdn(zoneName),
		createRequest,
	)

	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	zoneName, err := c.resolver.FindZoneByFQDN(ctx, fqdn, c.dns01Nameservers)
	if err != nil {
		return err
	}

	records, err := c.findTxtRecord(ctx, zoneName, fqdn)
	if err != nil {
		return err
	}

	for _, record := range records {
		// Only delete the record holding this challenge's value. Multiple
		// TXT records can share the same name (e.g. concurrent orders for
		// example.com and *.example.com, or racing renewals), and deleting
		// every name-matching record regardless of value would remove a
		// sibling challenge's record out from under it mid-validation.
		if record.Data != value {
			continue
		}

		_, err = c.client.Domains.DeleteRecord(ctx, util.UnFqdn(zoneName), record.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

// recordsPerPage is the page size requested when listing TXT records from
// the DigitalOcean API. The API defaults to a page size of 20 when no
// per_page value is supplied. findTxtRecord filters by name server-side
// (see below), so in practice a single page is virtually always enough;
// per_page combined with the pagination loop is only a safety net for the
// pathological case of many records sharing the same name.
const recordsPerPage = 200

// findTxtRecord returns every TXT record in zoneName named fqdn.
//
// It uses DigitalOcean's server-side type+name filter (RecordsByTypeAndName)
// rather than listing every TXT record in the zone and filtering client
// side. Besides needing far fewer requests against large zones, this also
// avoids a race: walking multiple pages of an unfiltered, unsnapshotted
// listing while another challenge concurrently creates/deletes records in
// the same zone can shift later pages and skip a record entirely. With a
// name filter, only records that actually share this name are ever
// returned, which shrinks that window to near zero.
//
// The pagination loop is kept as a defensive fallback in case a name is
// ever shared by more than recordsPerPage records; it is not expected to
// run more than once in practice.
// See https://github.com/cert-manager/cert-manager/issues/9099.
func (c *DNSProvider) findTxtRecord(ctx context.Context, zoneName, fqdn string) ([]godo.DomainRecord, error) {
	var records []godo.DomainRecord

	opt := &godo.ListOptions{Page: 1, PerPage: recordsPerPage}
	for {
		pageRecords, resp, err := c.client.Domains.RecordsByTypeAndName(
			ctx,
			util.UnFqdn(zoneName),
			"TXT",
			util.UnFqdn(fqdn),
			opt,
		)
		if err != nil {
			return nil, err
		}

		records = append(records, pageRecords...)

		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		opt.Page++
	}

	return records, nil
}
