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
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/client-go/rest"
)

// RestConfigWithUserAgent returns a copy of the Kubernetes REST config with
// the User Agent set which includes the optional component strings given.
func RestConfigWithUserAgent(restConfig *rest.Config, component ...string) *rest.Config {
	restConfig = rest.CopyConfig(restConfig)
	restConfig.UserAgent = fmt.Sprintf("%s/%s (%s) cert-manager/%s",
		strings.Join(append([]string{"cert-manager"}, component...), "-"),
		version(), VersionInfo().Platform, VersionInfo().GitCommit)
	return restConfig
}

// PrefixFromUserAgent takes the characters preceding the first /, quote
// unprintable character and then trim what's beyond the FieldManagerMaxLength
// limit.
// Taken from
// https://github.com/kubernetes/kubernetes/blob/9a75e7b0fd1b567f774a3373be640e19b33e7ef1/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go#L252
func PrefixFromUserAgent(u string) string {
	m := strings.Split(u, "/")[0]
	buf := bytes.NewBuffer(nil)
	for _, r := range m {
		// Ignore non-printable characters
		if !unicode.IsPrint(r) {
			continue
		}
		// Only append if we have room for it
		if buf.Len()+utf8.RuneLen(r) > validation.FieldManagerMaxLength {
			break
		}
		buf.WriteRune(r)
	}
	return buf.String()
}

// UserAgentRoundTripper implements the http.RoundTripper interface and adds a User-Agent
// header.
type userAgentRoundTripper struct {
	inner     http.RoundTripper
	userAgent string
}

// UserAgentRoundTripper returns a RoundTripper that functions identically to
// the provided 'inner' round tripper, other than also setting a user agent.
func UserAgentRoundTripper(inner http.RoundTripper, userAgent string) http.RoundTripper {
	return userAgentRoundTripper{
		inner:     inner,
		userAgent: userAgent,
	}
}

// RoundTrip implements http.RoundTripper
func (u userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", u.userAgent)
	return u.inner.RoundTrip(req)
}
