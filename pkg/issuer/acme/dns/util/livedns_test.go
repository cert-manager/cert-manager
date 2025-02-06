//go:build livedns_test

/*
Copyright 2025 The cert-manager Authors.

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

/*
Addition to the above license statement:

This file *may* contain code directly taken from the 'xenolf/lego' project.

A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package util

// The tests in this file connect to *live* DNS or DNS-over-HTTPS services,
// and rely on various DNS records which are out of the control of the cert-manager
// project. As such, these tests are:
// 1. More likely to flake due to network connectivity issues
// 2. Liable to break if the upstream DNS records change
// 3. Unable to run in restrictive computing environments
//    (such as MitM corporate proxies which block DNS / DNS-over-HTTPS)

// Because of the above, these tests live behind a build tag so they're not
// run by mistake.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

const (
	standardTimeout = time.Second * 5
)

func TestPreCheckDNSOverHTTPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), standardTimeout)
	defer cancel()

	ok, err := PreCheckDNS(ctx, "google.com.", "v=spf1 include:_spf.google.com ~all", []string{"https://8.8.8.8/dns-query"}, true)
	if err != nil || !ok {
		t.Errorf("preCheckDNS failed for dns-over-https (authoritative): ok=%v err=%s", ok, err.Error())
	}
}

func TestPreCheckDNSOverHTTPSNoAuthoritative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), standardTimeout)
	defer cancel()

	ok, err := PreCheckDNS(ctx, "google.com.", "v=spf1 include:_spf.google.com ~all", []string{"https://1.1.1.1/dns-query"}, false)
	if err != nil || !ok {
		t.Errorf("preCheckDNS failed for dns-over-https (non-authoritative): ok=%v err=%s", ok, err.Error())
	}
}

func TestPreCheckDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), standardTimeout)
	defer cancel()

	ok, err := PreCheckDNS(ctx, "google.com.", "v=spf1 include:_spf.google.com ~all", []string{"8.8.8.8:53"}, true)
	if err != nil || !ok {
		t.Errorf("preCheckDNS failed for dns on port 53 (authoritative): ok=%v err=%s", ok, err.Error())
	}
}

func TestPreCheckDNSNonAuthoritative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), standardTimeout)
	defer cancel()

	ok, err := PreCheckDNS(ctx, "google.com.", "v=spf1 include:_spf.google.com ~all", []string{"1.1.1.1:53"}, false)
	if err != nil || !ok {
		t.Errorf("preCheckDNS failed for dns on port 53 (non-authoritative): ok=%v err=%s", ok, err.Error())
	}
}

func TestCheckAuthoritativeNss(t *testing.T) {
	checkAuthoritativeNssTests := []struct {
		fqdn, value string
		ns          []string
		ok          bool
	}{
		// TXT RR w/ expected value
		{"8.8.8.8.asn.routeviews.org.", "151698.8.8.024", []string{"asnums.routeviews.org.:53"},
			true,
		},
		// No TXT RR
		{"ns1.google.com.", "", []string{"ns2.google.com.:53"},
			false,
		},
		// TXT RR w/ unexpected value
		{"8.8.8.8.asn.routeviews.org.", "fe01=", []string{"asnums.routeviews.org.:53"},
			false,
		},
	}

	for i, tt := range checkAuthoritativeNssTests {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), standardTimeout)
			defer cancel()

			ok, _ := checkAuthoritativeNss(ctx, tt.fqdn, tt.value, tt.ns)
			if ok != tt.ok {
				t.Errorf("%s: got %t; want %t", tt.fqdn, ok, tt.ok)
			}
		})
	}
}
