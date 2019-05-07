// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package acme provides an implementation of the
// Automatic Certificate Management Environment (ACME) spec.
// See https://tools.ietf.org/html/draft-ietf-acme-acme-09 for details.
//
// Most common scenarios will want to use autocert subdirectory instead,
// which provides automatic access to certificates from Let's Encrypt
// and any other ACME-based CA.
//
// This package is a work in progress and makes no API stability promises.
package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// LetsEncryptURL is the Directory endpoint of Let's Encrypt CA.
const LetsEncryptURL = "https://acme-v02.api.letsencrypt.org/directory"

const (
	// max length of a certificate chain
	maxChainLen = 5
	// max size of a certificate chain response, in bytes
	maxChainSize = (1 << 20) * maxChainLen

	// Max number of collected nonces kept in memory.
	// Expect usual peak of 1 or 2.
	maxNonces = 100

	// User-Agent, bump the version each time a change is made to the
	// handling of API requests.
	userAgent = "go-acme/2"
)

// Client is an ACME client.
// The only required field is Key. An example of creating a client with a new key
// is as follows:
//
// 	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	client := &Client{Key: key}
//
type Client struct {
	// Key is the account key used to register with a CA and sign requests.
	// Key.Public() must return a *rsa.PublicKey or *ecdsa.PublicKey.
	Key crypto.Signer

	// HTTPClient optionally specifies an HTTP client to use
	// instead of http.DefaultClient.
	HTTPClient *http.Client

	// DirectoryURL points to the CA directory endpoint.
	// If empty, LetsEncryptURL is used.
	// Mutating this value after a successful call of Client's Discover method
	// will have no effect.
	DirectoryURL string

	// UserAgent is an optional string that identifies this client and
	// version to the ACME server. It should be set to something like
	// "myclient/1.2.3".
	UserAgent string

	noncesMu sync.Mutex
	nonces   map[string]struct{} // nonces collected from previous responses

	urlMu      sync.Mutex // urlMu guards writes to dir and accountURL
	dir        *Directory // cached result of Client's Discover method
	accountURL string
}

// Discover performs ACME server discovery using c.DirectoryURL.
//
// It caches successful result. So, subsequent calls will not result in
// a network round-trip. This also means mutating c.DirectoryURL after successful call
// of this method will have no effect.
func (c *Client) Discover(ctx context.Context) (Directory, error) {
	c.urlMu.Lock()
	defer c.urlMu.Unlock()
	if c.dir != nil {
		return *c.dir, nil
	}

	dirURL := c.DirectoryURL
	if dirURL == "" {
		dirURL = LetsEncryptURL
	}
	res, err := c.get(ctx, dirURL)
	if err != nil {
		return Directory{}, err
	}
	defer res.Body.Close()
	c.addNonce(res.Header)
	if res.StatusCode != http.StatusOK {
		return Directory{}, responseError(res)
	}

	var v struct {
		NewNonce   string
		NewAccount string
		NewOrder   string
		NewAuthz   string
		RevokeCert string
		KeyChange  string
		Meta       struct {
			TermsOfService          string
			Website                 string
			CAAIdentities           []string
			ExternalAccountRequired bool
		}
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return Directory{}, err
	}
	c.dir = &Directory{
		NewNonceURL:             v.NewNonce,
		NewAccountURL:           v.NewAccount,
		NewOrderURL:             v.NewOrder,
		NewAuthzURL:             v.NewAuthz,
		RevokeCertURL:           v.RevokeCert,
		KeyChangeURL:            v.KeyChange,
		Terms:                   v.Meta.TermsOfService,
		Website:                 v.Meta.Website,
		CAA:                     v.Meta.CAAIdentities,
		ExternalAccountRequired: v.Meta.ExternalAccountRequired,
	}
	return *c.dir, nil
}

// CreateOrder creates a new certificate order. The input order argument is not
// modified and can be built using NewOrder.
func (c *Client) CreateOrder(ctx context.Context, order *Order) (*Order, error) {
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}

	req := struct {
		Identifiers []wireAuthzID `json:"identifiers"`
		NotBefore   string        `json:"notBefore,omitempty"`
		NotAfter    string        `json:"notAfter,omitempty"`
	}{
		Identifiers: make([]wireAuthzID, len(order.Identifiers)),
	}
	for i, id := range order.Identifiers {
		req.Identifiers[i] = wireAuthzID{
			Type:  id.Type,
			Value: id.Value,
		}
	}
	if !order.NotBefore.IsZero() {
		req.NotBefore = order.NotBefore.Format(time.RFC3339)
	}
	if !order.NotAfter.IsZero() {
		req.NotAfter = order.NotAfter.Format(time.RFC3339)
	}

	res, err := c.postWithJWSAccount(ctx, c.dir.NewOrderURL, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return nil, responseError(res)
	}
	var v wireOrder
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, err
	}
	l, err := resolveLocation(c.dir.NewOrderURL, res.Header)
	if err != nil {
		return nil, err
	}
	o := v.order(l, "")

	if o.Status == StatusInvalid {
		return nil, OrderInvalidError{o}
	}
	return o, nil
}

// FinalizeOrder finalizes an order using the Certificate Signing Request csr
// encoded in DER format. If the order has not been fully authorized,
// an OrderPendingError will be returned.
//
// After requesting finalization, FinalizOrder polls the order using WaitOrder
// until it is finalized and then fetches the associated certificate and returns
// it.
//
// Callers are encouraged to parse the returned certificate chain to ensure it
// is valid and has the expected attributes.
func (c *Client) FinalizeOrder(ctx context.Context, finalizeURL string, csr []byte) (der [][]byte, err error) {
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}

	req := struct {
		CSR string `json:"csr"`
	}{
		CSR: base64.RawURLEncoding.EncodeToString(csr),
	}

	res, err := c.postWithJWSAccount(ctx, finalizeURL, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, responseError(res)
	}
	var v wireOrder
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, err
	}
	l, err := resolveLocation(finalizeURL, res.Header)
	if err != nil {
		return nil, err
	}
	o := v.order(l, res.Header.Get("Retry-After"))
	if o.Status == StatusProcessing || o.Status == StatusPending {
		o, err = c.WaitOrder(ctx, o.URL)
		if err != nil {
			return nil, err
		}
	}
	if o.Status != StatusValid {
		return nil, fmt.Errorf("acme: unexpected order status %q", o.Status)
	}

	return c.GetCertificate(ctx, o.CertificateURL)
}

// GetOrder retrieves an order identified by url.
//
// If a caller needs to poll an order until its status is final,
// see the WaitOrder method.
func (c *Client) GetOrder(ctx context.Context, url string) (*Order, error) {
	res, err := c.postWithJWSAccount(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		err = responseError(res)
		return nil, err
	}
	var v wireOrder
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, err
	}
	return v.order(url, res.Header.Get("Retry-After")), nil
}

// WaitOrder waits for an order to transition from StatusProcessing to a final
// state (StatusValid/StatusInvalid), it retries the request until the order is
// final, ctx is cancelled by the caller, or an error response is received.
//
// It returns a non-nil Order only if its Status is StatusValid.  In all other
// cases WaitOrder returns an error. If the Status is StatusInvalid, the
// returned error will be of type OrderInvalidError. If the status is
// StatusPending, the returned error will be of type OrderPendingError.
func (c *Client) WaitOrder(ctx context.Context, url string) (*Order, error) {
	sleep := timeSleeper(ctx)
	for {
		o, err := c.GetOrder(ctx, url)
		if e, ok := err.(*Error); ok && e.StatusCode >= 500 && e.StatusCode <= 599 {
			// retriable 5xx error
			if err := sleep(retryAfter(e.Header.Get("Retry-After"))); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		switch o.Status {
		case StatusValid:
			return o, nil
		case StatusInvalid:
			return nil, OrderInvalidError{o}
		case StatusPending:
			return nil, OrderPendingError{o}
		case StatusProcessing: // continue retry loop
		default:
			return nil, fmt.Errorf("acme: unexpected order status %q", o.Status)
		}
		if err := sleep(o.RetryAfter); err != nil {
			return nil, err
		}
	}
}

// RevokeCert revokes a previously issued certificate cert, provided in DER
// format.
//
// If key is nil, the account must have been used to issue the certificate or
// have valid authorizations for all of the identifiers in the certificate. If
// key is provided, it must be the certificate's private key.
func (c *Client) RevokeCert(ctx context.Context, key crypto.Signer, cert []byte, reason CRLReasonCode) error {
	if _, err := c.Discover(ctx); err != nil {
		return err
	}

	body := &struct {
		Cert   string `json:"certificate"`
		Reason int    `json:"reason"`
	}{
		Cert:   base64.RawURLEncoding.EncodeToString(cert),
		Reason: int(reason),
	}
	var res *http.Response
	var err error
	if key == nil {
		res, err = c.postWithJWSAccount(ctx, c.dir.RevokeCertURL, body)
	} else {
		res, err = c.postWithJWSKey(ctx, key, c.dir.RevokeCertURL, body)
	}
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return responseError(res)
	}
	return nil
}

// CreateAccount creates a new account. It returns the account details from the
// server and does not modify the account argument that it is called with.
func (c *Client) CreateAccount(ctx context.Context, a *Account) (*Account, error) {
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}
	return c.doAccount(ctx, c.dir.NewAccountURL, false, a)
}

// GetAccount retrieves the account that the client is configured with.
func (c *Client) GetAccount(ctx context.Context) (*Account, error) {
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}
	return c.doAccount(ctx, c.dir.NewAccountURL, true, nil)
}

// UpdateAccount updates an existing account. It returns an updated account
// copy. The provided account is not modified.
func (c *Client) UpdateAccount(ctx context.Context, a *Account) (*Account, error) {
	return c.doAccount(ctx, a.URL, false, a)
}

// GetAuthorization retrieves an authorization identified by the given URL.
//
// If a caller needs to poll an authorization until its status is final,
// see the WaitAuthorization method.
func (c *Client) GetAuthorization(ctx context.Context, url string) (*Authorization, error) {
	res, err := c.postWithJWSAccount(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, responseError(res)
	}
	var v wireAuthz
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("acme: invalid response: %v", err)
	}
	return v.authorization(url), nil
}

// DeactivateAuthorization relinquishes an existing authorization identified by
// the given URL.
//
// If successful, the caller will be required to obtain a new authorization
// before a new certificate for the domain associated with the authorization is
// issued.
//
// It does not revoke existing certificates.
func (c *Client) DeactivateAuthorization(ctx context.Context, url string) error {
	res, err := c.postWithJWSAccount(ctx, url, json.RawMessage(`{"status":"deactivated"}`))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return responseError(res)
	}
	return nil
}

// WaitAuthorization polls an authorization at the given URL
// until it is in one of the final states, StatusValid or StatusInvalid,
// the ACME CA responded with a 4xx error code, or the context is done.
//
// It returns a non-nil Authorization only if its Status is StatusValid.
// In all other cases WaitAuthorization returns an error.
// If the Status is StatusInvalid, StatusDeactivated, or StatusRevoked the
// returned error will be of type AuthorizationError.
func (c *Client) WaitAuthorization(ctx context.Context, url string) (*Authorization, error) {
	sleep := sleeper(ctx)
	for {
		res, err := c.postWithJWSAccount(ctx, url, nil)
		if err != nil {
			return nil, err
		}
		if res.StatusCode >= 400 && res.StatusCode <= 499 {
			// Non-retriable error. For instance, Let's Encrypt may return 404 Not Found
			// when requesting an expired authorization.
			defer res.Body.Close()
			return nil, responseError(res)
		}

		retry := res.Header.Get("Retry-After")
		if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusAccepted {
			res.Body.Close()
			if err := sleep(retry); err != nil {
				return nil, err
			}
			continue
		}
		var raw wireAuthz
		err = json.NewDecoder(res.Body).Decode(&raw)
		res.Body.Close()
		if err != nil {
			return nil, err
		}
		switch raw.Status {
		case StatusValid:
			return raw.authorization(url), nil
		case StatusInvalid, StatusDeactivated, StatusRevoked:
			return nil, AuthorizationError{raw.authorization(url)}
		case StatusPending, StatusProcessing: // fall through to sleep
		default:
			return nil, fmt.Errorf("acme: unknown authorization status %q", raw.Status)
		}
		if err := sleep(retry); err != nil {
			return nil, err
		}
	}
}

// GetChallenge retrieves the current status of a challenge.
//
// A client typically polls a challenge status using this method.
func (c *Client) GetChallenge(ctx context.Context, url string) (*Challenge, error) {
	res, err := c.postWithJWSAccount(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, responseError(res)
	}
	v := wireChallenge{URL: url}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("acme: invalid response: %v", err)
	}
	return v.challenge(), nil
}

// AcceptChallenge informs the server that the client accepts one of its
// authorization challenges previously obtained with
// CreateOrder/GetAuthorization.
//
// The server will then perform the validation asynchronously.
func (c *Client) AcceptChallenge(ctx context.Context, chal *Challenge) (*Challenge, error) {
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}

	res, err := c.postWithJWSAccount(ctx, chal.URL, json.RawMessage(`{}`))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, responseError(res)
	}

	var v wireChallenge
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("acme: invalid response: %v", err)
	}
	return v.challenge(), nil
}

// DNS01ChallengeRecord returns a DNS record value for a dns-01 challenge response.
// A TXT record containing the returned value must be provisioned under
// "_acme-challenge" name of the domain being validated.
//
// The token argument is a Challenge.Token value.
func (c *Client) DNS01ChallengeRecord(token string) (string, error) {
	ka, err := keyAuth(c.Key.Public(), token)
	if err != nil {
		return "", err
	}
	b := sha256.Sum256([]byte(ka))
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// HTTP01ChallengeResponse returns the response for an http-01 challenge.
// Servers should respond with the value to HTTP requests at the URL path
// provided by HTTP01ChallengePath to validate the challenge and prove control
// over a domain name.
//
// The token argument is a Challenge.Token value.
func (c *Client) HTTP01ChallengeResponse(token string) (string, error) {
	return keyAuth(c.Key.Public(), token)
}

// HTTP01ChallengePath returns the URL path at which the response for an http-01 challenge
// should be provided by the servers.
// The response value can be obtained with HTTP01ChallengeResponse.
//
// The token argument is a Challenge.Token value.
func (c *Client) HTTP01ChallengePath(token string) string {
	return "/.well-known/acme-challenge/" + token
}

// doAccount creates, updates, and reads accounts.
//
// A non-nil acct argument indicates whether the intention is to mutate data of
// the Account. Only the Contact field can be updated.
func (c *Client) doAccount(ctx context.Context, url string, getExistingWithKey bool, acct *Account) (*Account, error) {
	req := struct {
		Contact     []string `json:"contact,omitempty"`
		TermsAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
		GetExisting bool     `json:"onlyReturnExisting,omitempty"`
	}{
		GetExisting: getExistingWithKey,
	}
	var accountURL string
	if url != c.dir.NewAccountURL {
		accountURL = url
	}
	if acct != nil {
		req.Contact = acct.Contact
		req.TermsAgreed = acct.TermsAgreed
	}
	res, err := c.retryPostJWS(ctx, c.Key, accountURL, url, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, responseError(res)
	}

	if getExistingWithKey {
		l, err := resolveLocation(url, res.Header)
		if err != nil {
			return nil, err
		}
		return c.doAccount(ctx, l, false, nil)
	}

	var v struct {
		Status  string
		Contact []string
		Orders  string
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("acme: invalid response: %v", err)
	}
	l, err := resolveLocation(url, res.Header)
	if err != nil {
		return nil, err
	}
	a := &Account{
		URL:       l,
		Status:    v.Status,
		Contact:   v.Contact,
		OrdersURL: v.Orders,
	}
	if a.URL == "" {
		a.URL = url
	}
	c.urlMu.Lock()
	defer c.urlMu.Unlock()
	c.accountURL = a.URL
	return a, nil
}

// cacheAccount ensures that the account URL is cached and returns it.
func (c *Client) cacheAccountURL(ctx context.Context) (string, error) {
	c.urlMu.Lock()
	defer c.urlMu.Unlock()
	if c.accountURL != "" {
		return c.accountURL, nil
	}
	res, err := c.postWithJWSKey(ctx, c.Key, c.dir.NewAccountURL, json.RawMessage(`{"onlyReturnExisting":true}`))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", responseError(res)
	}
	l, err := resolveLocation(c.dir.NewAccountURL, res.Header)
	if err != nil {
		return "", err
	}
	c.accountURL = l
	return c.accountURL, nil
}

func (c *Client) postWithJWSKey(ctx context.Context, key crypto.Signer, url string, body interface{}) (*http.Response, error) {
	return c.retryPostJWS(ctx, key, "", url, body)
}

func (c *Client) postWithJWSAccount(ctx context.Context, url string, body interface{}) (*http.Response, error) {
	accountURL, err := c.cacheAccountURL(ctx)
	if err != nil {
		return nil, err
	}
	return c.retryPostJWS(ctx, c.Key, accountURL, url, body)
}

// retryPostJWS will retry calls to postJWS if there is a badNonce error,
// clearing the stored nonces after each error.
// If the response was 4XX-5XX, then responseError is called on the body,
// the body is closed, and the error returned.
func (c *Client) retryPostJWS(ctx context.Context, key crypto.Signer, accountURL, url string, body interface{}) (*http.Response, error) {
	sleep := sleeper(ctx)
	for {
		res, err := c.postJWS(ctx, key, accountURL, url, body)
		if err != nil {
			return nil, err
		}
		// handle errors 4XX-5XX with responseError
		if res.StatusCode >= 400 && res.StatusCode <= 599 {
			err := responseError(res)
			res.Body.Close()
			if ae, ok := err.(*Error); ok && ae.Type == "urn:ietf:params:acme:error:badNonce" {
				// clear any nonces that we might've stored that might now be
				// considered bad
				c.clearNonces()
				retry := res.Header.Get("Retry-After")
				if err := sleep(retry); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		return res, nil
	}
}

// postJWS signs the body with the given key and POSTs it to the provided url.
// The body argument must be JSON-serializable.
// The accountURL should be empty for account creation and certificate revocation.
func (c *Client) postJWS(ctx context.Context, key crypto.Signer, accountURL, url string, body interface{}) (*http.Response, error) {
	nonce, err := c.popNonce(ctx)
	if err != nil {
		return nil, err
	}
	b, err := jwsEncodeJSON(body, key, accountURL, url, nonce)
	if err != nil {
		return nil, err
	}
	res, err := c.post(ctx, url, "application/jose+json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	c.addNonce(res.Header)
	return res, nil
}

// popNonce returns a nonce value previously stored with c.addNonce
// or fetches a fresh one.
func (c *Client) popNonce(ctx context.Context) (string, error) {
	c.noncesMu.Lock()
	defer c.noncesMu.Unlock()
	if len(c.nonces) == 0 {
		return c.fetchNonce(ctx)
	}
	var nonce string
	for nonce = range c.nonces {
		delete(c.nonces, nonce)
		break
	}
	return nonce, nil
}

// clearNonces clears any stored nonces
func (c *Client) clearNonces() {
	c.noncesMu.Lock()
	defer c.noncesMu.Unlock()
	c.nonces = make(map[string]struct{})
}

// addNonce stores a nonce value found in h (if any) for future use.
func (c *Client) addNonce(h http.Header) {
	v := nonceFromHeader(h)
	if v == "" {
		return
	}
	c.noncesMu.Lock()
	defer c.noncesMu.Unlock()
	if len(c.nonces) >= maxNonces {
		return
	}
	if c.nonces == nil {
		c.nonces = make(map[string]struct{})
	}
	c.nonces[v] = struct{}{}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) get(ctx context.Context, urlStr string) (*http.Response, error) {
	req, err := c.newRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, req)
}

func (c *Client) head(ctx context.Context, urlStr string) (*http.Response, error) {
	req, err := c.newRequest("HEAD", urlStr, nil)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, req)
}

func (c *Client) post(ctx context.Context, urlStr, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.newRequest("POST", urlStr, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.do(ctx, req)
}

func (c *Client) newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	ua := userAgent
	if c.UserAgent != "" {
		ua += " " + c.UserAgent
	}
	req.Header.Set("User-Agent", ua)
	return req, nil
}

func (c *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	res, err := c.httpClient().Do(req.WithContext(ctx))
	if err != nil {
		select {
		case <-ctx.Done():
			// Prefer the unadorned context error.
			// (The acme package had tests assuming this, previously from ctxhttp's
			// behavior, predating net/http supporting contexts natively)
			// TODO(bradfitz): reconsider this in the future. But for now this
			// requires no test updates.
			return nil, ctx.Err()
		default:
			return nil, err
		}
	}
	return res, nil
}

func (c *Client) fetchNonce(ctx context.Context) (string, error) {
	resp, err := c.head(ctx, c.dir.NewNonceURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	nonce := nonceFromHeader(resp.Header)
	if nonce == "" {
		if resp.StatusCode > 299 {
			return "", responseError(resp)
		}
		return "", errors.New("acme: nonce not found")
	}
	return nonce, nil
}

func nonceFromHeader(h http.Header) string {
	return h.Get("Replay-Nonce")
}

func (c *Client) GetCertificate(ctx context.Context, url string) ([][]byte, error) {
	res, err := c.postWithJWSAccount(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := ioutil.ReadAll(io.LimitReader(res.Body, maxChainSize+1))
	if err != nil {
		return nil, fmt.Errorf("acme: error getting certificate: %v", err)
	}
	if len(data) > maxChainSize {
		return nil, errors.New("acme: certificate chain is too big")
	}
	var chain [][]byte
	for {
		var p *pem.Block
		p, data = pem.Decode(data)
		if p == nil {
			if len(chain) == 0 {
				return nil, errors.New("acme: invalid PEM certificate chain")
			}
			break
		}
		if len(chain) == maxChainLen {
			return nil, errors.New("acme: certificate chain is too long")
		}
		if p.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("acme: invalid PEM block type %q", p.Type)
		}
		chain = append(chain, p.Bytes)
	}
	return chain, nil
}

// responseError creates an error of Error type from resp.
func responseError(resp *http.Response) error {
	// don't care if ReadAll returns an error:
	// json.Unmarshal will fail in that case anyway
	b, _ := ioutil.ReadAll(resp.Body)
	e := &wireError{Status: resp.StatusCode}
	if err := json.Unmarshal(b, e); err != nil {
		// this is not a regular error response:
		// populate detail with anything we received,
		// e.Status will already contain HTTP response code value
		e.Detail = string(b)
		if e.Detail == "" {
			e.Detail = resp.Status
		}
	}
	return e.error(resp.Header)
}

// sleeper returns a function that accepts the Retry-After HTTP header value
// and an increment that's used with backoff to increasingly sleep on
// consecutive calls until the context is done. If the Retry-After header
// cannot be parsed, then backoff is used with a maximum sleep time of 10
// seconds.
func sleeper(ctx context.Context) func(ra string) error {
	sleep := timeSleeper(ctx)
	return func(ra string) error {
		return sleep(retryAfter(ra))
	}
}

func timeSleeper(ctx context.Context) func(time.Time) error {
	var count int
	return func(t time.Time) error {
		d := backoff(count, 10*time.Second)
		count++
		if !t.IsZero() {
			d = t.Sub(timeNow())
		}
		wakeup := time.NewTimer(d)
		defer wakeup.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wakeup.C:
			return nil
		}
	}
}

// retryAfter parses a Retry-After HTTP header value,
// trying to convert v into an int (seconds) or use http.ParseTime otherwise.
func retryAfter(v string) time.Time {
	if i, err := strconv.Atoi(v); err == nil {
		return timeNow().Add(time.Duration(i) * time.Second)
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// backoff computes a duration after which an n+1 retry iteration should occur
// using truncated exponential backoff algorithm.
//
// The n argument is always bounded between 0 and 30.
// The max argument defines upper bound for the returned value.
func backoff(n int, max time.Duration) time.Duration {
	if n < 0 {
		n = 0
	}
	if n > 30 {
		n = 30
	}
	var d time.Duration
	if x, err := rand.Int(rand.Reader, big.NewInt(1000)); err == nil {
		d = time.Duration(x.Int64()) * time.Millisecond
	}
	d += time.Duration(1<<uint(n)) * time.Second
	if d > max {
		return max
	}
	return d
}

// keyAuth generates a key authorization string for a given token.
func keyAuth(pub crypto.PublicKey, token string) (string, error) {
	th, err := JWKThumbprint(pub)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, th), nil
}

func resolveLocation(base string, h http.Header) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u, err = u.Parse(h.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("acme: error parsing Location: %s", err)
	}
	return u.String(), nil
}

// timeNow is useful for testing for fixed current time.
var timeNow = time.Now
