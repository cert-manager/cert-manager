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
	"time"
)

const (
	maxDelay       = 3 * time.Second
	maxRetries     = 5
	maxRetries404  = 3
)

// RetryBackoff is the ACME client RetryBackoff which is modified
// to act upon badNonce and 404 errors. All other retries will be handled by cert-manager.
// Since we cannot check the exact error this is best effort.
func RetryBackoff(n int, r *http.Request, resp *http.Response) time.Duration {

	// According to the spec badNonce is urn:ietf:params:acme:error:badNonce.
	// However, we cannot use the request body in here as it is closed already.
	// So we're using its status code instead: 400
	//
	// A 404 Not Found can also occur transiently due to ACME server replication lag
	// (e.g. Let's Encrypt), where a resource created via POST is not yet visible on
	// a read replica. See: https://github.com/cert-manager/cert-manager/issues/8939
	retryable := resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound
	if !retryable {
		return -1
	}

	// Differentiate retry limits based on error type.
	// badNonce (400): more retries needed as nonce desync can persist.
	// 404: fewer retries as replication lag is typically very short-lived.
	if resp.StatusCode == http.StatusNotFound {
		if n >= maxRetries404 {
			return -1
		}
	} else if n > maxRetries {
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
