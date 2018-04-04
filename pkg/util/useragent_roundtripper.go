package util

import (
	"net/http"
)

// CertManagerUserAgent is the user agent that http clients in this codebase should use
var CertManagerUserAgent = "jetstack-cert-manager/" + version()

// UserAgentRoundTripper implements the http.RoundTripper interface and adds a User-Agent
// header.
type userAgentRoundTripper struct {
	inner http.RoundTripper
}

// UserAgentRoundTripper returns a RoundTripper that functions identically to
// the provided 'inner' round tripper, other than also setting a user agent.
func UserAgentRoundTripper(inner http.RoundTripper) http.RoundTripper {
	return userAgentRoundTripper{
		inner: inner,
	}
}

// RoundTrip implements http.RoundTripper
func (u userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", CertManagerUserAgent)
	return u.inner.RoundTrip(req)
}
