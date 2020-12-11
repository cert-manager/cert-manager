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
	"crypto/rand"
	"math/big"
	"net/http"
	"time"
)

const (
	maxDelay   = 3 * time.Second
	maxRetries = 5
)

// RetryBackoff is the ACME client RetryBackoff which is modified
// to act upon badNonce errors. all other retries will be handled by cert-manager.
// Since we cannot check the exact error this is best effort.
func RetryBackoff(n int, r *http.Request, resp *http.Response) time.Duration {

	// According to the spec badNonce is urn:ietf:params:acme:error:badNonce.
	// However, we can not use the request body in here as it is closed already.
	// So we're using its status code instead: 400
	if resp.StatusCode != http.StatusBadRequest {
		return -1
	}

	// don't retry more than 6 times, if we get 6 nonce mismatches something is quite wrong
	if n > maxRetries {
		return -1
	} else if n < 1 {
		// n is used for the backoff time below
		n = 1
	}

	var jitter time.Duration
	if x, err := rand.Int(rand.Reader, big.NewInt(1000)); err == nil {
		jitter = (1 + time.Duration(x.Int64())) * time.Millisecond
	}

	d := time.Duration(1<<uint(n-1))*time.Second + jitter
	if d > maxDelay {
		return maxDelay
	}
	return d
}
