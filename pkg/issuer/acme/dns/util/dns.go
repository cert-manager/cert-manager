package util

import "fmt"

// DNS01Record returns a DNS record which will fulfill the `dns-01` challenge
// TODO: move this into a non-generic place by resolving import cycle in dns package
func DNS01Record(domain, value string) (string, string, int) {
	return fmt.Sprintf("_acme-challenge.%s.", domain), value, 60
}
