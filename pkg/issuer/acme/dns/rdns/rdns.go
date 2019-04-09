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

// Package rdns provides a DNS provider for resolving DNS-01 challenge by
// calling RDNS api to set TXT record.
// Related project:
// https://github.com/rancher/rdns-server
*/

package rdns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

const (
	AuthorizationHeader = "Authorization"
	ContentTypeHeader = "Content-Type"
	ContentTypeJSON = "application/json"
	txtPathPattern = "%s/domain/_acme-challenge.%s/txt"
)

type DNSProvider struct {
	client DnsClient
}

func NewDNSProvider() (*DNSProvider, error) {
	apiEndpoint := os.Getenv("RDNS_API_ENDPOINT")
	token := os.Getenv("RDNS_TOKEN")
	return NewDNSProviderCredential(apiEndpoint, token)
}

func NewDNSProviderCredential(apiEndpoint, token string) (*DNSProvider, error) {
	if apiEndpoint == "" {
		return nil, fmt.Errorf("rdns api endpoint is empty")
	}

	if token == "" {
		return nil, fmt.Errorf("rdns token is missing")
	}

	dnsClient := DnsClient{
		httpClient: http.DefaultClient,
		base:       apiEndpoint,
		token:      token,
	}
	return &DNSProvider{
		client: dnsClient,
	}, nil
}

func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	return d.client.SetTXTRecord(domain, keyAuth)
}

func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	return d.client.DeleteDNSRecord(domain)
}

func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 180 * time.Second, 5 * time.Second
}

type DnsClient struct {
	httpClient *http.Client
	base       string
	token      string
}

func (d *DnsClient) SetTXTRecord(domain, text string) error {
	url := fmt.Sprintf(txtPathPattern, d.base, domain)
	payload := map[string]string{
		"text": text,
	}
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, url, buf)
	if err != nil {
		return err
	}
	request.Header.Set(AuthorizationHeader, fmt.Sprintf("Bearer %s", d.token))
	request.Header.Set(ContentTypeHeader, ContentTypeJSON)
	resp, err := d.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("expect 200, got %v. Error: %s", resp.StatusCode, string(data))
	}
	return nil
}

func (d *DnsClient) DeleteDNSRecord(domain string) error {
	url := fmt.Sprintf(txtPathPattern, d.base, domain)
	request, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	request.Header.Set(AuthorizationHeader, fmt.Sprintf("Bearer %s", d.token))
	request.Header.Set(ContentTypeHeader, ContentTypeJSON)
	resp, err := d.httpClient.Do(request)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("expect 200, got %v. Error: %s", resp.StatusCode, string(data))
	}

	return err
}
