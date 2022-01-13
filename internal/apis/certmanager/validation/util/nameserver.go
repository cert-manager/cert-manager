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

package util

import (
	"fmt"
	"net"
	"strings"
)

var defaultRFC2136Port = "53"

// ValidNameserver validates the given nameserver for the RFC2136 provider, returning the sanitized nameserver - if valid - in the form "<host>:<port>".
func ValidNameserver(nameserver string) (string, error) {
	nameserver = strings.TrimSpace(nameserver)

	if nameserver == "" {
		return "", fmt.Errorf("RFC2136 nameserver missing")
	}

	// SplitHostPort Behavior
	// nameserver          host                port    err
	// 8.8.8.8             ""                  ""      missing port in address
	// 8.8.8.8:            "8.8.8.8"           ""      <nil>
	// 8.8.8.8.8:53        "8.8.8.8"           53      <nil>
	// [2001:db8::1]       ""                  ""      missing port in address
	// [2001:db8::1]:      "2001:db8::1"       ""      <nil>
	// [2001:db8::1]:53    "2001:db8::1"       53      <nil>
	// nameserver.com      ""                  ""      missing port in address
	// nameserver.com:     "nameserver.com"    ""      <nil>
	// nameserver.com:53   "nameserver.com"    53      <nil>
	// :53                 ""                  53      <nil>
	host, port, err := net.SplitHostPort(nameserver)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			// net.JoinHostPort expect IPv6 address to be unenclosed
			host = strings.Trim(nameserver, "[]")
		} else {
			return "", fmt.Errorf("RFC2136 nameserver is invalid: %s", err.Error())
		}
	}

	if host == "" {
		return "", fmt.Errorf("RFC2136 nameserver has no host defined, %v", nameserver)
	}

	if port == "" {
		port = defaultRFC2136Port
	}

	return net.JoinHostPort(host, port), nil
}
