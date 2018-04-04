package util

import (
	"net/http"
)

// UserAgentRoundTripper implements the http.RoundTripper interface and adds a User-Agent
// header.
type userAgentRoundTripper struct {
	inner http.RoundTripper
}

// CertManagerUserAgent is the user agent that http clients in this codebase should use
const CertManagerUserAgent = "jetstack-cert-manager/" + AppVersion

// UserAgentRoundTripper returns a RoundTripper that functions identically to
// the provided 'inner' round tripper, other than also setting a user agent.
func UserAgentRoundTripper(inner http.RoundTripper) http.RoundTripper {
	return UserAgentRoundTripper{
		inner: inner,
	}
}

// RoundTrip implements http.RoundTripper
func (u userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", CertManagerUserAgent)
	return u.inner.RoundTrip(req)
}
