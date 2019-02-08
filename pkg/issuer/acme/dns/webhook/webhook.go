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

package webhook

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

const (
	maxBodyLength = 5 * 1024 * 1024
)

type DNSProvider struct {
	httpClient       *http.Client
	url              string
	metadata         map[string]string
	dns01Nameservers []string
}

type httpResponse struct {
	httpStatusCode int
	body           []byte
	truncated      bool
}

func NewDNSProvider(url string, metadata map[string]string, skipTLSVerify bool, webhookCA []byte, dns01Nameservers []string) (*DNSProvider, error) {
	rootCAs := x509.NewCertPool()

	if !skipTLSVerify {
		if ok := rootCAs.AppendCertsFromPEM(webhookCA); !ok {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
	}

	tlsConfig := &tls.Config{ClientCAs: rootCAs, InsecureSkipVerify: skipTLSVerify}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: time.Duration(10 * time.Second),
	}

	return &DNSProvider{
		httpClient:       client,
		url:              url,
		metadata:         metadata,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

func (c *DNSProvider) Present(domain, fqdn, value string) error {
	err := c.sendRequest(v1alpha1.WebhookPayload{
		Operation: v1alpha1.WebhookPresentOperation,
		FQDN:      util.UnFqdn(fqdn),
		Domain:    domain,
		Value:     value,
		Metadata:  c.metadata,
	})

	return err
}

func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	err := c.sendRequest(v1alpha1.WebhookPayload{
		Operation: v1alpha1.WebhookCleanupOperation,
		FQDN:      util.UnFqdn(fqdn),
		Domain:    domain,
		Value:     value,
		Metadata:  c.metadata,
	})

	return err
}

func (c *DNSProvider) sendRequest(payload v1alpha1.WebhookPayload) error {
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	httpResponse, err := sendPost(c.httpClient, c.url, jsonBytes)
	if err != nil {
		return err
	}

	webhookResponse := new(v1alpha1.WebhookResponse)
	err = json.Unmarshal(httpResponse.body, webhookResponse)
	if err != nil {
		return fmt.Errorf("webhook returned http code \"%v\". failed to unmarshal webhook response: %v", httpResponse.httpStatusCode, err)
	}

	if webhookResponse.Result != v1alpha1.WebhookResponseResultSuccess {
		return fmt.Errorf("webhook returned non-successful status %q with the following reason: %s", webhookResponse.Result, webhookResponse.Reason)
	}

	return nil
}

func sendPost(client *http.Client, url string, payload []byte) (*httpResponse, error) {
	response, err := client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// truncate body if it exceeds maxBodyLength and set the appropriate flag
	var truncated bool
	response.Body = http.MaxBytesReader(nil, response.Body, maxBodyLength)
	buf, err := ioutil.ReadAll(response.Body)
	if err != nil {
		truncated = true
	}

	return &httpResponse{
		httpStatusCode: response.StatusCode,
		body:           buf,
		truncated:      truncated,
	}, nil

}
