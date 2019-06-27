// +build !go1.8

package utilization

// net.Resolver.LookupAddr was added in Go 1.8, and net.LookupAddr does not have
// a controllable timeout, so we skip the optional full_hostname on pre 1.8
// versions.

func getFQDN(candidateIPs []string) string {
	return ""
}
