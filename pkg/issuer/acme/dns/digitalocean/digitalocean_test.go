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

package digitalocean

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	doLiveTest bool
	doToken    string
	doDomain   string
)

func init() {
	doToken = os.Getenv("DIGITALOCEAN_TOKEN")
	doDomain = os.Getenv("DIGITALOCEAN_DOMAIN")
	if len(doToken) > 0 && len(doDomain) > 0 {
		doLiveTest = true
	}
}

func TestNewDNSProviderValid(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "")
	_, err := NewDNSProviderCredentials("123", util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "")
	_, err := NewDNSProvider(util.RecursiveNameservers, "cert-manager-test")
	assert.EqualError(t, err, "DigitalOcean token missing")
}

func TestDigitalOceanPresent(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(doToken, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)

	err = provider.Present(t.Context(), doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestDigitalOceanCleanUp(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(doToken, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)

	err = provider.CleanUp(t.Context(), doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestGetHostedZonePrefersMostSpecificManagedDomain(t *testing.T) {
	service := &fakeDomainsService{
		zones: map[string]struct{}{
			"sub.example.com": {},
			"example.com":     {},
		},
	}
	provider := &DNSProvider{domainsClient: service}

	zoneName, err := provider.getHostedZone(t.Context(), "_acme-challenge.foo.sub.example.com.")
	assert.NoError(t, err)
	assert.Equal(t, "sub.example.com.", zoneName)
	assert.Equal(t, []string{
		"_acme-challenge.foo.sub.example.com",
		"foo.sub.example.com",
		"sub.example.com",
	}, service.getCalls)
}

func TestGetHostedZoneFallsBackToParentManagedDomain(t *testing.T) {
	service := &fakeDomainsService{
		zones: map[string]struct{}{
			"example.com": {},
		},
	}
	provider := &DNSProvider{domainsClient: service}

	zoneName, err := provider.getHostedZone(t.Context(), "_acme-challenge.foo.sub.example.com.")
	assert.NoError(t, err)
	assert.Equal(t, "example.com.", zoneName)
	assert.Equal(t, []string{
		"_acme-challenge.foo.sub.example.com",
		"foo.sub.example.com",
		"sub.example.com",
		"example.com",
	}, service.getCalls)
}

func TestDigitalOceanPresentUsesManagedDomain(t *testing.T) {
	service := &fakeDomainsService{
		zones: map[string]struct{}{
			"example.com": {},
		},
	}
	provider := &DNSProvider{domainsClient: service}

	err := provider.Present(t.Context(), "", "_acme-challenge.foo.sub.example.com.", "123d==")
	assert.NoError(t, err)
	assert.Equal(t, []createRecordCall{
		{
			domain: "example.com",
			record: godo.DomainRecordEditRequest{
				Type: "TXT",
				Name: "_acme-challenge.foo.sub.example.com.",
				Data: "123d==",
				TTL:  60,
			},
		},
	}, service.createCalls)
}

func TestDigitalOceanCleanUpUsesManagedDomain(t *testing.T) {
	service := &fakeDomainsService{
		zones: map[string]struct{}{
			"example.com": {},
		},
		records: map[string][]godo.DomainRecord{
			"example.com": {
				{
					ID:   10,
					Type: "TXT",
					Name: "_acme-challenge.foo.sub",
					Data: "123d==",
				},
			},
		},
	}
	provider := &DNSProvider{domainsClient: service}

	err := provider.CleanUp(t.Context(), "", "_acme-challenge.foo.sub.example.com.", "123d==")
	assert.NoError(t, err)
	assert.Equal(t, []deleteRecordCall{
		{domain: "example.com", id: 10},
	}, service.deleteCalls)
}

type fakeDomainsService struct {
	godo.DomainsService

	zones       map[string]struct{}
	records     map[string][]godo.DomainRecord
	getCalls    []string
	createCalls []createRecordCall
	deleteCalls []deleteRecordCall
}

type createRecordCall struct {
	domain string
	record godo.DomainRecordEditRequest
}

type deleteRecordCall struct {
	domain string
	id     int
}

func (f *fakeDomainsService) Get(_ context.Context, name string) (*godo.Domain, *godo.Response, error) {
	f.getCalls = append(f.getCalls, name)

	if _, ok := f.zones[name]; ok {
		return &godo.Domain{Name: name}, nil, nil
	}

	return nil, nil, &godo.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusNotFound},
		Message:  "Resource not found",
	}
}

func (f *fakeDomainsService) RecordsByType(_ context.Context, domain, ofType string, _ *godo.ListOptions) ([]godo.DomainRecord, *godo.Response, error) {
	if ofType != "TXT" {
		return nil, nil, assert.AnError
	}

	return f.records[domain], nil, nil
}

func (f *fakeDomainsService) CreateRecord(_ context.Context, domain string, createRequest *godo.DomainRecordEditRequest) (*godo.DomainRecord, *godo.Response, error) {
	f.createCalls = append(f.createCalls, createRecordCall{
		domain: domain,
		record: *createRequest,
	})

	return &godo.DomainRecord{}, nil, nil
}

func (f *fakeDomainsService) DeleteRecord(_ context.Context, domain string, id int) (*godo.Response, error) {
	f.deleteCalls = append(f.deleteCalls, deleteRecordCall{domain: domain, id: id})

	return nil, nil
}
