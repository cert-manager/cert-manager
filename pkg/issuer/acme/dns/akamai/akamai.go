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

// Package akamai implements a DNS provider for solving the DNS-01
// challenge using Akamai Edge DNS.
// See https://developer.akamai.com/api/cloud_security/edge_dns_zone_management/v2.html
package akamai

import (
	"context"
	"fmt"
	"strings"

	dns "github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/dns"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/edgegrid"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
	"github.com/go-logr/logr"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// OpenEdgegridDNSService enables mocking and required functions
type OpenEdgegridDNSService interface {
	GetRecord(ctx context.Context, zone string, name string, recordType string) (*dns.RecordBody, error)
	RecordSave(ctx context.Context, rec *dns.RecordBody, zone string) error
	RecordUpdate(ctx context.Context, rec *dns.RecordBody, zone string) error
	RecordDelete(ctx context.Context, rec *dns.RecordBody, zone string) error
}

// OpenDNSClient holds Akamai's client to create authorization header.
type OpenDNSClient struct {
	client dns.DNS
}

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers       []string
	serviceConsumerDomain  string
	dnsclient              OpenEdgegridDNSService
	TTL                    int
	findHostedDomainByFqdn func(context.Context, string, []string) (string, error)
	isNotFound             func(error) bool
	log                    logr.Logger
}

// NewDNSProvider returns a DNSProvider instance configured for Akamai.
func NewDNSProvider(serviceConsumerDomain, clientToken, clientSecret, accessToken string, dns01Nameservers []string) (*DNSProvider, error) {

	// required Aka OpenEdgegrid creds + non empty dnsservers list
	if serviceConsumerDomain == "" || clientToken == "" || clientSecret == "" || accessToken == "" || len(dns01Nameservers) < 1 {
		return nil, fmt.Errorf("edgedns: Provider creation failed. Missing required arguments")
	}

	dnsp := &DNSProvider{
		dns01Nameservers:       dns01Nameservers,
		serviceConsumerDomain:  serviceConsumerDomain,
		dnsclient:              &OpenDNSClient{},
		findHostedDomainByFqdn: findHostedDomainByFqdn,
		isNotFound:             isNotFound,
		log:                    logf.Log.WithName("akamai-dns"),
		TTL:                    300,
	}
	cfg, err := edgegrid.New(func(c *edgegrid.Config) {
		c.Host = serviceConsumerDomain
		c.ClientToken = clientToken
		c.ClientSecret = clientSecret
		c.AccessToken = accessToken
		c.MaxBody = 131072
	})
	if err != nil {
		return nil, fmt.Errorf("edgedns: Provider config creation failed: %w", err)
	}

	s, err := session.New(
		session.WithSigner(cfg),
	)
	if err != nil {
		return nil, fmt.Errorf("edgedns: Error creating session: %w", err)
	}

	dnsp.dnsclient.(*OpenDNSClient).client = dns.Client(s)

	return dnsp, nil
}

func findHostedDomainByFqdn(ctx context.Context, fqdn string, ns []string) (string, error) {
	zone, err := util.FindZoneByFqdn(ctx, fqdn, ns)
	if err != nil {
		return "", err
	}

	return util.UnFqdn(zone), nil
}

// Present creates/updates a TXT record to fulfill the dns-01 challenge.
func (a *DNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	logf.FromContext(ctx).V(logf.DebugLevel).Info("entering Present", "domain", domain, "fqdn", fqdn, "value", value)

	hostedDomain, err := a.findHostedDomainByFqdn(ctx, fqdn, a.dns01Nameservers)
	if err != nil {
		return fmt.Errorf("edgedns: failed to determine hosted domain for %q: %w", fqdn, err)
	}
	hostedDomain = util.UnFqdn(hostedDomain)
	logf.FromContext(ctx).V(logf.DebugLevel).Info("calculated hosted domain", "hostedDomain", hostedDomain)

	recordName, err := makeTxtRecordName(fqdn, hostedDomain)
	if err != nil {
		return fmt.Errorf("edgedns: failed to create TXT record name: %w", err)
	}
	logf.FromContext(ctx).V(logf.DebugLevel).Info("calculated TXT record name", "recordName", recordName)

	record, err := a.dnsclient.GetRecord(ctx, hostedDomain, recordName, "TXT")
	if err != nil && !a.isNotFound(err) {
		return fmt.Errorf("edgedns: failed to retrieve TXT record: %w", err)
	}

	if err == nil && record == nil {
		return fmt.Errorf("edgedns: unknown error")
	}

	if record != nil {
		logf.FromContext(ctx).V(logf.InfoLevel).Info("edgedns: TXT record already exists. Updating target")

		if containsValue(record.Target, value) {
			// have a record and have entry already
			return nil
		}

		record.Target = append(record.Target, `"`+value+`"`)
		record.TTL = a.TTL

		err = a.dnsclient.RecordUpdate(ctx, record, hostedDomain)
		if err != nil {
			return fmt.Errorf("edgedns: failed to update TXT record: %w", err)
		}

		return nil
	}

	record = &dns.RecordBody{
		Name:       recordName,
		RecordType: "TXT",
		TTL:        a.TTL,
		Target:     []string{`"` + value + `"`},
	}

	err = a.dnsclient.RecordSave(ctx, record, hostedDomain)
	if err != nil {
		return fmt.Errorf("edgedns: failed to create TXT record: %w", err)
	}

	return nil
}

// CleanUp removes/updates the TXT record matching the specified parameters.
func (a *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	logf.FromContext(ctx).V(logf.DebugLevel).Info("entering CleanUp", "domain", domain, "fqdn", fqdn, "value", value)

	hostedDomain, err := a.findHostedDomainByFqdn(ctx, fqdn, a.dns01Nameservers)
	if err != nil {
		return fmt.Errorf("edgedns: failed to determine hosted domain for %q: %w", fqdn, err)
	}
	hostedDomain = util.UnFqdn(hostedDomain)
	logf.FromContext(ctx).V(logf.DebugLevel).Info("calculated hosted domain", "hostedDomain", hostedDomain)

	recordName, err := makeTxtRecordName(fqdn, hostedDomain)
	if err != nil {
		return fmt.Errorf("edgedns: failed to create TXT record name: %w", err)
	}
	logf.FromContext(ctx).V(logf.DebugLevel).Info("calculated TXT record name", "recordName", recordName)

	existingRec, err := a.dnsclient.GetRecord(ctx, hostedDomain, recordName, "TXT")
	if err != nil {
		if a.isNotFound(err) {
			return nil
		}
		return fmt.Errorf("edgedns: failed to retrieve TXT record: %w", err)
	}

	if existingRec == nil {
		return fmt.Errorf("edgedns: unknown failure")
	}

	if len(existingRec.Target) == 0 {
		return fmt.Errorf("edgedns: TXT record is invalid")
	}

	if !containsValue(existingRec.Target, value) {
		return nil
	}

	var newRData []string
	for _, val := range existingRec.Target {
		tval := strings.Trim(val, `"`)
		if tval == value {
			continue
		}
		newRData = append(newRData, val)
	}

	if len(newRData) > 0 {
		existingRec.Target = newRData
		logf.FromContext(ctx).V(logf.DebugLevel).Info("updating Akamai TXT record", "recordName", existingRec.Name, "data", newRData)
		err = a.dnsclient.RecordUpdate(ctx, existingRec, hostedDomain)
		if err != nil {
			return fmt.Errorf("edgedns: TXT record update failed: %w", err)
		}

		return nil
	}

	logf.FromContext(ctx).V(logf.DebugLevel).Info("deleting Akamai TXT record", "recordName", existingRec.Name)
	err = a.dnsclient.RecordDelete(ctx, existingRec, hostedDomain)
	if err != nil {
		return fmt.Errorf("edgedns: TXT record delete failed: %w", err)
	}

	return nil
}

func containsValue(values []string, value string) bool {
	for _, val := range values {
		if strings.Trim(val, `"`) == value {
			return true
		}
	}

	return false
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}

	_, ok := err.(*dns.Error)
	return ok
}

func makeTxtRecordName(fqdn, hostedDomain string) (string, error) {

	recName := util.UnFqdn(fqdn)
	if !strings.HasSuffix(recName, hostedDomain) {
		return "", fmt.Errorf("fqdn %q is not part of %q", fqdn, hostedDomain)
	}

	return recName, nil
}

// GetRecord gets a single Recordset as RecordBody. Sets Akamai OPEN Edgegrid API
// global variable.
func (o OpenDNSClient) GetRecord(ctx context.Context, zone string, name string, recordType string) (*dns.RecordBody, error) {
	recordResponse, err := o.client.GetRecord(ctx, dns.GetRecordRequest{
		RecordType: recordType,
		Name:       name,
		Zone:       zone,
	})

	if err != nil {
		return nil, err
	}

	return &dns.RecordBody{
		Name:       recordResponse.Name,
		TTL:        recordResponse.TTL,
		Target:     recordResponse.Target,
		Active:     recordResponse.Active,
		RecordType: recordResponse.RecordType,
	}, nil
}

// RecordSave is a function that saves the given zone in the given RecordBody.
func (o OpenDNSClient) RecordSave(ctx context.Context, rec *dns.RecordBody, zone string) error {
	return o.client.CreateRecord(ctx, dns.CreateRecordRequest{
		Record: rec,
		Zone:   zone,
	})
}

// RecordUpdate is a function that updates the given zone in the given RecordBody.
func (o OpenDNSClient) RecordUpdate(ctx context.Context, rec *dns.RecordBody, zone string) error {
	return o.client.UpdateRecord(ctx, dns.UpdateRecordRequest{
		Record: rec,
		Zone:   zone,
	})
}

// RecordDelete is a function that deletes the given zone in the given RecordBody.
func (o OpenDNSClient) RecordDelete(ctx context.Context, rec *dns.RecordBody, zone string) error {
	return o.client.DeleteRecord(ctx, dns.DeleteRecordRequest{
		RecordType: rec.RecordType,
		Name:       rec.Name,
		Zone:       zone,
	})
}
