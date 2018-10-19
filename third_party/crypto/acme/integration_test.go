// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build integration_test

package acme_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"reflect"
	"testing"

	"golang.org/x/crypto/acme"
)

// This test works with Pebble and Let's Encrypt staging.
// For pebble use: ACME_DIRECTORY_URL=https://localhost:14000/dir go test -tags integration_test
// For Let's Encrypt you'll need a publicly accessible HTTP server like `ngrok http 8080` and then
// TEST_HOST=xxx.ngrok.io:8080 ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory TEST_ACCOUNT_GET=1 TEST_REVOKE=1 go test -tags integration_test
func TestIntegration(t *testing.T) {
	dir := os.Getenv("ACME_DIRECTORY_URL")
	testAccountGet := os.Getenv("TEST_ACCOUNT_GET") != ""
	testRevoke := os.Getenv("TEST_REVOKE") != ""
	testHost := os.Getenv("TEST_HOST")
	if testHost == "" {
		testHost = "localhost:5002"
	}
	testIdentifier, listenPort, _ := net.SplitHostPort(testHost)
	if dir == "" {
		t.Fatal("ACME_DIRECTORY_URL is required")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &acme.Client{
		Key:          key,
		DirectoryURL: dir,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	a := &acme.Account{
		Contact:     []string{"mailto:user@example.com"},
		TermsAgreed: true,
	}
	na, err := c.CreateAccount(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(a.Contact, na.Contact) {
		t.Errorf("na.Contact = %q; want %q", na.Contact, a.Contact)
	}
	if na.URL == "" {
		t.Fatal("empty na.URL")
	}

	// this endpoint is not supported by pebble, so put it behind a flag
	if testAccountGet {
		na, err = c.GetAccount(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a.Contact, na.Contact) {
			t.Errorf("na.Contact = %q; want %q", na.Contact, a.Contact)
		}
	}

	order, err := c.CreateOrder(context.Background(), acme.NewOrder(testIdentifier))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := c.GetAuthorization(context.Background(), order.Authorizations[0])
	if err != nil {
		t.Fatal(err)
	}

	var challenge *acme.Challenge
	for _, ch := range auth.Challenges {
		if ch.Type == "http-01" {
			challenge = ch
			break
		}
	}
	if challenge == nil {
		t.Fatal("missing http-01 challenge")
	}

	l, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		t.Errorf("error listening for challenge: %s", err)
	}
	defer l.Close()
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != c.HTTP01ChallengePath(challenge.Token) {
			w.WriteHeader(404)
			return
		}
		res, _ := c.HTTP01ChallengeResponse(challenge.Token)
		w.Write([]byte(res))
	}))

	_, err = c.AcceptChallenge(context.Background(), challenge)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.WaitAuthorization(context.Background(), order.Authorizations[0])
	if err != nil {
		t.Fatal(err)
	}

	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{testIdentifier}}, certKey)
	der, err := c.FinalizeOrder(context.Background(), order.FinalizeURL, csr)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatal(err)
	}
	if cert.DNSNames[0] != testIdentifier {
		t.Errorf("unexpected DNSNames %v", cert.DNSNames)
	}

	if testRevoke {
		if err := c.RevokeCert(context.Background(), certKey, der[0], acme.CRLReasonUnspecified); err != nil {
			t.Fatal(err)
		}
	}
}
