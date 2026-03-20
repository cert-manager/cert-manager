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
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

const (
	maxDelay          = 3 * time.Second
	maxRetries        = 5
	rateLimitMaxDelay = 60 * time.Second
	rateLimitRetries  = 10
)

// RetryBackoff is the ACME client RetryBackoff which is modified
// to act upon badNonce errors and rate limit (429) responses.
// All other retries will be handled by cert-manager.
// Since we cannot check the exact error this is best effort.
func RetryBackoff(n int, r *http.Request, resp *http.Response) time.Duration {
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return rateLimitBackoff(n, resp)
	case http.StatusBadRequest:
		return badNonceBackoff(n)
	default:
		return -1
	}
}

// rateLimitBackoff handles HTTP 429 Too Many Requests responses by respecting
// the Retry-After header if present, or falling back to exponential backoff.
// This is important for ACME providers like ZeroSSL that enforce strict rate
// limits and return 429 responses during certificate issuance flows.
func rateLimitBackoff(n int, resp *http.Response) time.Duration {
	if n > rateLimitRetries {
		return -1
	}

	// No need for a cryptographically secure RNG here
	jitter := 1 + time.Millisecond*time.Duration(rand.Int64N(1000)) // #nosec G404

	// Respect the Retry-After header if the server provided one.
	if v := resp.Header.Get("Retry-After"); v != "" {
		if retryAfterSec, err := strconv.Atoi(v); err == nil && retryAfterSec > 0 {
			d := time.Duration(retryAfterSec)*time.Second + jitter
			if d > rateLimitMaxDelay {
				return rateLimitMaxDelay
			}
			return d
		}
		if t, err := http.ParseTime(v); err == nil {
			d := time.Until(t) + jitter
			if d <= 0 {
				return jitter
			}
			if d > rateLimitMaxDelay {
				return rateLimitMaxDelay
			}
			return d
		}
	}

	// Fall back to exponential backoff starting at 2 seconds.
	exponent := uint(0)
	if temp := n; temp >= 0 {
		exponent = uint(temp)
	}

	d := time.Duration(1<<exponent)*2*time.Second + jitter
	if d > rateLimitMaxDelay {
		return rateLimitMaxDelay
	}
	return d
}

// badNonceBackoff handles HTTP 400 Bad Request responses which typically
// indicate badNonce errors from ACME servers.
func badNonceBackoff(n int) time.Duration {
	// don't retry more than 6 times, if we get 6 nonce mismatches something is quite wrong
	if n > maxRetries {
		return -1
	}

	// No need for a cryptographically secure RNG here
	jitter := 1 + time.Millisecond*time.Duration(rand.Int64N(1000)) // #nosec G404

	// the exponent is calculated slightly contrived to allow the gosec:G115
	// linter to recognise the safe type conversion.
	// simple formula: exponent = max(0, n-1)
	exponent := uint(0)
	if temp := n - 1; temp >= 0 {
		exponent = uint(temp)
	}

	d := time.Duration(1<<exponent)*time.Second + jitter
	if d > maxDelay {
		return maxDelay
	}
	return d
}
