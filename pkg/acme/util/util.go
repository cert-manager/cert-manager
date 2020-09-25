/*
Copyright 2020 The Jetstack cert-manager contributors.

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

	"github.com/jetstack/cert-manager/pkg/logs"
)

// RetryBackoff is the ACME client RetryBackoff that filters rate limit errors to our retry loop
// inspired by acme/http.go
func RetryBackoff(n int, r *http.Request, res *http.Response) time.Duration {
	var jitter time.Duration
	if x, err := rand.Int(rand.Reader, big.NewInt(1000)); err == nil {
		// Set the minimum to 1ms to avoid a case where
		// an invalid Retry-After value is parsed into 0 below,
		// resulting in the 0 returned value which would unintentionally
		// stop the retries.
		jitter = (1 + time.Duration(x.Int64())) * time.Millisecond
	}
	if _, ok := res.Header["Retry-After"]; ok {
		// if Retry-After is set we should
		// error and let the cert-manager logic retry instead
		return -1
	}

	// don't retry more than 10 times
	if n > 10 {
		return -1
	}

	// classic backoff here in case we got no reply
	// eg. flakes
	if n < 1 {
		n = 1
	}

	d := time.Duration(1<<uint(n-1))*time.Second + jitter
	logs.Log.V(logs.DebugLevel).WithValues("backoff", d).Info("Hit an error in golang.org/x/crypto/acme, retrying")
	if d > 10*time.Second {
		return 10 * time.Second
	}
	return d
}
