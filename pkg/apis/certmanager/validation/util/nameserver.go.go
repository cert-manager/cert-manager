package util

import (
	"fmt"
	"net"
	"strings"
)

var defaultRFC2136Port = "53"

// This function make a valid nameserver as per RFC2136
func ValidNameserver(nameserver string) (string, error) {

	if nameserver == "" {
		return "", fmt.Errorf("RFC2136 nameserver missing")
	}

	// SplitHostPort Behavior
	// namserver           host                port    err
	// 8.8.8.8             ""                  ""      missing port in address
	// 8.8.8.8:            "8.8.8.8"           ""      <nil>
	// 8.8.8.8.8:53        "8.8.8.8"           53      <nil>
	// nameserver.com      ""                  ""      missing port in address
	// nameserver.com:     "nameserver.com"    ""      <nil>
	// nameserver.com:53   "nameserver.com"    53      <nil>
	// :53                 ""                  53      <nil>
	host, port, err := net.SplitHostPort(strings.TrimSpace(nameserver))

	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			host = nameserver
		}
	}

	if port == "" {
		port = defaultRFC2136Port
	}

	if host != "" {
		if ipaddr := net.ParseIP(host); ipaddr == nil {
			return "", fmt.Errorf("RFC2136 nameserver must be a valid IP Address, not %v", host)
		}
	} else {
		return "", fmt.Errorf("RFC2136 nameserver has no IP Address defined, %v", nameserver)
	}

	nameserver = host + ":" + port

	return nameserver, nil
}
