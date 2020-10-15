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
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// wireError is a subset of fields of the Problem Details object
// as described in https://tools.ietf.org/html/rfc7807#section-3.1.
// it is used to check for badNonce errors in the retry logic
type wireError struct {
	Status   int
	Type     string
	Detail   string
	Instance string
}

func (e *wireError) error(h http.Header) *acme.Error {
	return &acme.Error{
		StatusCode:  e.Status,
		ProblemType: e.Type,
		Detail:      e.Detail,
		Instance:    e.Instance,
		Header:      h,
	}
}

// RetryBackoff is the ACME client RetryBackoff that does not retry
// all retries will be handled by cert-manager
func RetryBackoff(n int, r *http.Request, resp *http.Response) time.Duration {

	// reaging the error response to check for any errors we MUST retry
	// don't care if ReadAll returns an error:
	// json.Unmarshal will fail in that case anyway
	b, _ := ioutil.ReadAll(resp.Body)
	e := &wireError{Status: resp.StatusCode}
	if err := json.Unmarshal(b, e); err != nil {
		// this is not a regular error response:
		// populate detail with anything we received,
		// e.Status will already contain HTTP response code value
		e.Detail = string(b)
		if e.Detail == "" {
			e.Detail = resp.Status
		}
	}

	// According to the spec badNonce is urn:ietf:params:acme:error:badNonce.
	// However, ACME servers in the wild return their versions of the error.
	// See https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-5.4
	// and https://github.com/letsencrypt/boulder/blob/0e07eacb/docs/acme-divergences.md#section-66.
	if strings.HasSuffix(strings.ToLower(e.error(resp.Header).ProblemType), ":badnonce") {
		// don't retry more than 10 times, if we get 10 nonce mismatches something is quite wrong
		if n > 10 {
			return -1
		} else if n < 1 {
			// n is used for the backoff time below
			n = 1
		}

		var jitter time.Duration
		if x, err := rand.Int(rand.Reader, big.NewInt(1000)); err == nil {
			// Set the minimum to 1ms to avoid a case where
			// an invalid Retry-After value is parsed into 0 below,
			// resulting in the 0 returned value which would unintentionally
			// stop the retries.
			jitter = (1 + time.Duration(x.Int64())) * time.Millisecond
		}

		d := time.Duration(1<<uint(n-1))*time.Second + jitter
		if d > 3*time.Second {
			return 3 * time.Second
		}
		return d
	}

	// do not retry any non badNonce errors
	return -1
}
