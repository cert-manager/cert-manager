/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package webhook

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

const (
	maxBodyLength = 5 * 1024 * 1024

	presentOperation operation = "present"
	cleanupOperation operation = "cleanup"
)

type operation string

type WebhookPayload struct {
	Operation operation `json:"operation"`

	// Identifier is the record that should have a TXT record set for, e.g. _acme-challenge.example.com
	Identifier string `json:"identifier"`

	// Key is the value that the TXT record should hold for this domain
	Key string `json:"key"`

	// Metadata is arbitrary additional metadata passed to the plugin from the Issuer resource.
	// This may contain a reference to a secret resource, containing secret data specific to this
	// configuration of the plugin.
	Metadata map[string]string `json:"metadata,omitempty"`
}

type DNSProvider struct {
	httpClient       *http.Client
	url              string
	metadata         map[string]string
	dns01Nameservers []string
}

func NewDNSProvider(url string, metadata map[string]string, skipTLSVerify bool, webhookCA []byte, dns01Nameservers []string) (*DNSProvider, error) {
	rootCAs, err := x509.SystemCertPool()
	if rootCAs == nil || err != nil {
		glog.Errorf("can't instantiate system CA pool, falling back to empty CA pool: %s", err)
	}

	if ok := rootCAs.AppendCertsFromPEM(webhookCA); !ok {
		glog.Infof("no certs appended, using system certs only")
	}

	tlsConfig := &tls.Config{ClientCAs: rootCAs, InsecureSkipVerify: skipTLSVerify}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: time.Duration(30 * time.Second),
	}

	return &DNSProvider{
		httpClient:       client,
		url:              url,
		metadata:         metadata,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

func (c *DNSProvider) Present(domain, fqdn, value string) error {
	body, err := c.sendRequest(WebhookPayload{Operation: presentOperation, Identifier: util.UnFqdn(fqdn), Key: value, Metadata: c.metadata})
	if len(body) > 0 {
		glog.Infof("response body: %q", body)
	}

	return err
}

func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	body, err := c.sendRequest(WebhookPayload{Operation: cleanupOperation, Identifier: util.UnFqdn(fqdn), Key: value, Metadata: c.metadata})
	if len(body) > 0 {
		glog.Infof("response body: %q", body)
	}

	return err
}

func (c *DNSProvider) sendRequest(payload WebhookPayload) (responseBody string, err error) {
	jsonString, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	response, err := c.httpClient.Post(c.url, "application/json", bytes.NewReader(jsonString))
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 HTTP code returned: %d", response.StatusCode)
	}

	defer response.Body.Close()

	response.Body = http.MaxBytesReader(nil, response.Body, maxBodyLength)
	buf, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Sprintf("truncated: %s", buf), nil
	}

	return string(buf), nil
}
