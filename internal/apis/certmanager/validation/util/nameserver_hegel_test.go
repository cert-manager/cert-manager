/*
Copyright 2026 The cert-manager Authors.

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

package util

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"hegel.dev/go/hegel"
)

// TestValidNameserverProperties checks the normalization laws of
// ValidNameserver for any host (IPv4, IPv6 or DNS name):
//
//   - a host with an explicit port is returned as JoinHostPort(host, port)
//   - a bare host, with or without a trailing colon, gets the default port 53
//   - the result is a fixed point: validating it again returns it unchanged
//
// plus the error cases: empty or whitespace input and a port with no host.
func TestValidNameserverProperties(t *testing.T) {
	addrString := func(a netip.Addr) string { return a.String() }
	hosts := hegel.OneOf(
		hegel.Map(hegel.IPAddresses().IPv4(), addrString),
		hegel.Map(hegel.IPAddresses().IPv6(), addrString),
		hegel.Domains().MaxLength(30),
	)

	hegel.Test(t, func(ht *hegel.T) {
		host := hegel.Draw(ht, hosts)
		port := hegel.Draw(ht, hegel.Integers(0, 65535))

		withPort := net.JoinHostPort(host, strconv.Itoa(port))
		got, err := ValidNameserver(withPort)
		if err != nil {
			ht.Fatalf("rejected %q: %v", withPort, err)
		}
		if got != withPort {
			ht.Fatalf("normalized %q to %q, want it unchanged", withPort, got)
		}

		// Bare host, optionally with a trailing colon: default port 53.
		bare := host
		if strings.Contains(host, ":") {
			bare = "[" + host + "]"
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			bare += ":"
		}
		want := net.JoinHostPort(host, "53")
		got, err = ValidNameserver(bare)
		if err != nil {
			ht.Fatalf("rejected %q: %v", bare, err)
		}
		if got != want {
			ht.Fatalf("normalized %q to %q, want %q", bare, got, want)
		}

		// Idempotence.
		again, err := ValidNameserver(got)
		if err != nil || again != got {
			ht.Fatalf("not a fixed point: %q -> %q, %v", got, again, err)
		}
	})

	for _, invalid := range []string{"", "   ", ":53"} {
		if got, err := ValidNameserver(invalid); err == nil {
			t.Errorf("expected error for %q, got %q", invalid, got)
		}
	}
	if _, err := ValidNameserver(fmt.Sprintf("8.8.8:8:%d", 53)); err == nil {
		t.Error("expected error for host with too many colons")
	}
}
