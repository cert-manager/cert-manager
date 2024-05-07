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

	dns "github.com/akamai/AkamaiOPEN-edgegrid-golang/configdns-v2"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/edgegrid"
	"github.com/go-logr/logr"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// OpenEdgegridDNSService enables mocking and required functions
type OpenEdgegridDNSService interface {
	GetRecord(zone string, name string, recordType string) (*dns.RecordBody, error)
	RecordSave(rec *dns.RecordBody, zone string) error
	RecordUpdate(rec *dns.RecordBody, zone string) error
	RecordDelete(rec *dns.RecordBody, zone string) error
}

// OpenDNSConfig contains akamai's config to create authorization header.
type OpenDNSConfig struct {
	config edgegrid.Config
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
		dnsclient:              &OpenDNSConfig{},
		findHostedDomainByFqdn: findHostedDomainByFqdn,
		isNotFound:             isNotFound,
		log:                    logf.Log.WithName("akamai-dns"),
		TTL:                    300,
	}
	dnsp.dnsclient.(*OpenDNSConfig).config = edgegrid.Config{
		Host:         serviceConsumerDomain,
		ClientToken:  clientToken,
		ClientSecret: clientSecret,
		AccessToken:  accessToken,
		MaxBody:      131072,
	}

	dns.Init(dnsp.dnsclient.(*OpenDNSConfig).config)

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
	logf.V(logf.DebugLevel).Infof("entering Present. domain: %s, fqdn: %s, value: %s", domain, fqdn, value)

	hostedDomain, err := a.findHostedDomainByFqdn(ctx, fqdn, a.dns01Nameservers)
	if err != nil {
		return fmt.Errorf("edgedns: failed to determine hosted domain for %q: %w", fqdn, err)
	}
	hostedDomain = util.UnFqdn(hostedDomain)
	logf.V(logf.DebugLevel).Infof("hostedDomain: %s", hostedDomain)

	recordName, err := makeTxtRecordName(fqdn, hostedDomain)
	if err != nil {
		return fmt.Errorf("edgedns: failed to create TXT record name: %w", err)
	}
	logf.V(logf.DebugLevel).Infof("recordName: %s", recordName)

	record, err := a.dnsclient.GetRecord(hostedDomain, recordName, "TXT")
	if err != nil && !a.isNotFound(err) {
		return fmt.Errorf("edgedns: failed to retrieve TXT record: %w", err)
	}

	if err == nil && record == nil {
		return fmt.Errorf("edgedns: unknown error")
	}

	if record != nil {
		logf.V(logf.InfoLevel).Infof("edgedns: TXT record already exists. Updating target")

		if containsValue(record.Target, value) {
			// have a record and have entry already
			return nil
		}

		record.Target = append(record.Target, `"`+value+`"`)
		record.TTL = a.TTL

		err = a.dnsclient.RecordUpdate(record, hostedDomain)
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

	err = a.dnsclient.RecordSave(record, hostedDomain)
	if err != nil {
		return fmt.Errorf("edgedns: failed to create TXT record: %w", err)
	}

	return nil
}

// CleanUp removes/updates the TXT record matching the specified parameters.
func (a *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	logf.V(logf.DebugLevel).Infof("entering CleanUp. domain: %s, fqdn: %s, value: %s", domain, fqdn, value)

	hostedDomain, err := a.findHostedDomainByFqdn(ctx, fqdn, a.dns01Nameservers)
	if err != nil {
		return fmt.Errorf("edgedns: failed to determine hosted domain for %q: %w", fqdn, err)
	}
	hostedDomain = util.UnFqdn(hostedDomain)
	logf.V(logf.DebugLevel).Infof("hostedDomain: %s", hostedDomain)

	recordName, err := makeTxtRecordName(fqdn, hostedDomain)
	if err != nil {
		return fmt.Errorf("edgedns: failed to create TXT record name: %w", err)
	}
	logf.V(logf.DebugLevel).Infof("recordName: %s", recordName)

	existingRec, err := a.dnsclient.GetRecord(hostedDomain, recordName, "TXT")
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
		logf.V(logf.DebugLevel).Infof("updating Akamai TXT record: %s, data: %s", existingRec.Name, newRData)
		err = a.dnsclient.RecordUpdate(existingRec, hostedDomain)
		if err != nil {
			return fmt.Errorf("edgedns: TXT record update failed: %w", err)
		}

		return nil
	}

	logf.V(logf.DebugLevel).Infof("deleting Akamai TXT record %s", existingRec.Name)
	err = a.dnsclient.RecordDelete(existingRec, hostedDomain)
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

	_, ok := err.(*dns.RecordError)
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
func (o OpenDNSConfig) GetRecord(zone string, name string, recordType string) (*dns.RecordBody, error) {

	dns.Config = o.config

	return dns.GetRecord(zone, name, recordType)
}

// RecordSave is a function that saves the given zone in the given RecordBody.
func (o OpenDNSConfig) RecordSave(rec *dns.RecordBody, zone string) error {

	return rec.Save(zone)
}

// RecordUpdate is a function that updates the given zone in the given RecordBody.
func (o OpenDNSConfig) RecordUpdate(rec *dns.RecordBody, zone string) error {

	return rec.Update(zone)
}

// RecordDelete is a function that deletes the given zone in the given RecordBody.
func (o OpenDNSConfig) RecordDelete(rec *dns.RecordBody, zone string) error {

	return rec.Delete(zone)
}
