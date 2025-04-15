/*
Copyright 2022 The cert-manager Authors.

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

package certificaterequests

import (
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// This test ensures that when a Certificate object is serialized in
// preparation for a Certificate Apply call. Only object meta/type and spec
// field should be present.
func Test_serializeApply(t *testing.T) {
	// Expected serialized Certificate Apply object. Should only contain base
	// type object, object meta object, and spec. status should be empty. Empty
	// spec should be deterministic.
	const (
		expReg      = `^{"kind":"CertificateRequest","apiVersion":"cert-manager.io/v1","metadata":{.*},"spec":{.*},"status":{}}$`
		expEmptyReg = `^{"kind":"CertificateRequest","apiVersion":"cert-manager.io/v1","metadata":{.*},"spec":{"issuerRef":{"name":""},"request":null},"status":{}}$`
		numJobs     = 10000
	)

	var wg sync.WaitGroup
	jobs := make(chan int)

	wg.Add(numJobs)
	for range 3 {
		go func() {
			for j := range jobs {
				t.Run("fuzz_"+strconv.Itoa(j), func(t *testing.T) {
					var req cmapi.CertificateRequest
					fuzz.New().NilChance(0.5).Fuzz(&req)

					// Test regex with non-empty spec.
					reqData, err := serializeApply(&req)
					assert.NoError(t, err)
					assert.Regexp(t, expReg, string(reqData))

					// Test round trip preserves the spec.
					var rtReq cmapi.CertificateRequest
					assert.NoError(t, json.Unmarshal(reqData, &rtReq))
					assert.Equal(t, req.Spec, rtReq.Spec)

					// String match on empty spec.
					req.Spec = cmapi.CertificateRequestSpec{}
					reqData, err = serializeApply(&req)
					assert.NoError(t, err)
					assert.Regexp(t, expEmptyReg, string(reqData))

					wg.Done()
				})
			}
		}()
	}

	for i := range numJobs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

// This test ensures that when a Certificate object is serialized in
// preparation for a Certificate status Apply call. Only the required
// metadata/type fields are present, and only empty spec fields are set. We
// also ensure that all Certificate status fields are tagged omitempty, and are
// not serialized if unset.
func Test_serializeApplyStatus(t *testing.T) {
	// Expected serialized Certificate Apply object. Should only contain base
	// meta/type object, empty spec. Status should be matched both via regex, and
	// when empty.
	const (
		expReg   = `^{"kind":"CertificateRequest","apiVersion":"cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{"issuerRef":{"name":""},"request":null},"status":{.*}}$`
		expEmpty = `{"kind":"CertificateRequest","apiVersion":"cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{"issuerRef":{"name":""},"request":null},"status":{}}`
		numJobs  = 10000
	)

	var wg sync.WaitGroup
	jobs := make(chan int)

	wg.Add(numJobs)
	for range 3 {
		go func() {
			for j := range jobs {
				t.Run("fuzz_"+strconv.Itoa(j), func(t *testing.T) {
					var req cmapi.CertificateRequest
					fuzz.New().NilChance(0.5).Fuzz(&req)
					req.Name = "foo"
					req.Namespace = "bar"

					// Test regex with non-empty status.
					reqData, err := serializeApplyStatus(&req)
					assert.NoError(t, err)
					assert.Regexp(t, expReg, string(reqData))

					// Test round trip preserves the status.
					var rtReq cmapi.CertificateRequest
					assert.NoError(t, json.Unmarshal(reqData, &rtReq))
					assert.Equal(t, req.Status, rtReq.Status)

					// String match on empty status.
					req.Status = cmapi.CertificateRequestStatus{}
					reqData, err = serializeApplyStatus(&req)
					assert.NoError(t, err)
					assert.Equal(t, expEmpty, string(reqData))

					wg.Done()
				})
			}
		}()
	}

	for i := range numJobs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}
