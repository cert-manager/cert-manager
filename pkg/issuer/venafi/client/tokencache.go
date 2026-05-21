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

package client

import (
	"sync"
	"time"
)

// tokenCache stores a single OAuth access token with its expiry time.
// It is safe for concurrent use. A zero-value tokenCache is valid and contains
// no cached token.
type tokenCache struct {
	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// isValid reports whether the cache holds a non-empty token that has not yet expired.
func (tc *tokenCache) isValid() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.accessToken != "" && time.Now().Before(tc.expiresAt)
}

// get returns the cached access token and its expiry time.
// Callers should check isValid before relying on the returned values.
func (tc *tokenCache) get() (accessToken string, expiresAt time.Time) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.accessToken, tc.expiresAt
}

// set stores a new access token and its expiry time in the cache.
func (tc *tokenCache) set(accessToken string, expiresAt time.Time) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.accessToken = accessToken
	tc.expiresAt = expiresAt
}

// AuthFailedError is returned by VerifyCredentials when the Venafi endpoint
// rejected the supplied credentials (e.g. HTTP 401/403). It is distinct from
// a transient network error, which does not wrap this type.
type AuthFailedError struct {
	// Err is the underlying error returned by the Venafi SDK.
	Err error
}

func (e AuthFailedError) Error() string {
	return "OAuth token request failed: " + e.Err.Error()
}

func (e AuthFailedError) Unwrap() error {
	return e.Err
}
