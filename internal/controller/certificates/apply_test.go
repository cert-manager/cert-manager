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

package certificates

import (
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func Test_serializeApply(t *testing.T) {
	const (
		expReg  = `^{"kind":"Certificate","apiVersion":"cert-manager.io/v1","metadata":{.*},"spec":{.*},"status":{}}$`
		numJobs = 10000
	)

	var wg sync.WaitGroup
	jobs := make(chan int)

	wg.Add(numJobs)
	for range 3 {
		go func() {
			for j := range jobs {
				t.Run("fuzz_"+strconv.Itoa(j), func(t *testing.T) {
					var crt cmapi.Certificate
					fuzz.New().NilChance(0.5).Fuzz(&crt)
					crt.ManagedFields = nil

					crtData, err := serializeApply(&crt)
					assert.NoError(t, err)
					assert.Regexp(t, expReg, string(crtData))

					// Test round trip serializing Certificate preserved the spec.
					var rtCrt cmapi.Certificate
					assert.NoError(t, json.Unmarshal(crtData, &rtCrt))
					assert.Equal(t, rtCrt.Spec, crt.Spec)

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
		expReg   = `^{"kind":"Certificate","apiVersion":"cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{"secretName":"","issuerRef":{"name":""}},"status":{.*}$`
		expEmpty = `{"kind":"Certificate","apiVersion":"cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{"secretName":"","issuerRef":{"name":""}},"status":{}}`
		numJobs  = 10000
	)

	var wg sync.WaitGroup
	jobs := make(chan int)

	wg.Add(numJobs)
	for range 3 {
		go func() {
			for j := range jobs {
				t.Run("fuzz_"+strconv.Itoa(j), func(t *testing.T) {
					var crt cmapi.Certificate
					fuzz.New().NilChance(0.5).Fuzz(&crt)
					crt.Name = "foo"
					crt.Namespace = "bar"

					// Test regex with non-empty status.
					crtData, err := serializeApplyStatus(&crt)
					assert.NoError(t, err)
					assert.Regexp(t, expReg, string(crtData))

					// String match on empty status.
					crt.Status = cmapi.CertificateStatus{}
					crtData, err = serializeApplyStatus(&crt)
					assert.NoError(t, err)
					assert.Equal(t, expEmpty, string(crtData))

					// Test round trip serializing Certificate preserved the status.
					var rtCrt cmapi.Certificate
					assert.NoError(t, json.Unmarshal(crtData, &rtCrt))
					assert.Equal(t, rtCrt.Status, crt.Status)

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
