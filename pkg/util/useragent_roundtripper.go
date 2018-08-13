/*
Copyright 2018 The Jetstack cert-manager contributors.

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
