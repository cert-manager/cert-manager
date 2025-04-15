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

package issuers

import (
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func Test_serializeApplyIssuerStatus(t *testing.T) {
	const (
		expReg   = `^{"kind":"Issuer","apiVersion":"cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{},"status":{.*}$`
		expEmpty = `{"kind":"Issuer","apiVersion":"cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{},"status":{}}`
		numJobs  = 10000
	)

	var wg sync.WaitGroup
	jobs := make(chan int)

	wg.Add(numJobs)
	for range 3 {
		go func() {
			for j := range jobs {
				t.Run("fuzz_"+strconv.Itoa(j), func(t *testing.T) {
					var issuer cmapi.Issuer
					fuzz.New().NilChance(0.5).Fuzz(&issuer)
					issuer.Name = "foo"
					issuer.Namespace = "bar"

					// Test regex with non-empty status.
					issuerData, err := serializeApplyIssuerStatus(&issuer)
					assert.NoError(t, err)
					assert.Regexp(t, expReg, string(issuerData))

					// Test round trip preserves the status.
					var rtIssuer cmapi.Issuer
					assert.NoError(t, json.Unmarshal(issuerData, &rtIssuer))
					assert.Equal(t, issuer.Status, rtIssuer.Status)

					// String match on empty status.
					issuer.Status = cmapi.IssuerStatus{}
					issuerData, err = serializeApplyIssuerStatus(&issuer)
					assert.NoError(t, err)
					assert.Equal(t, expEmpty, string(issuerData))

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

func Test_serializeApplyClusterIssuerStatus(t *testing.T) {
	const (
		expReg   = `^{"kind":"ClusterIssuer","apiVersion":"cert-manager.io/v1","metadata":{"name":"foo","creationTimestamp":null},"spec":{},"status":{.*}$`
		expEmpty = `{"kind":"ClusterIssuer","apiVersion":"cert-manager.io/v1","metadata":{"name":"foo","creationTimestamp":null},"spec":{},"status":{}}`
		numJobs  = 10000
	)

	var wg sync.WaitGroup
	jobs := make(chan int)

	wg.Add(numJobs)
	for range 3 {
		go func() {
			for j := range jobs {
				t.Run("fuzz_"+strconv.Itoa(j), func(t *testing.T) {
					var issuer cmapi.ClusterIssuer
					fuzz.New().NilChance(0.5).Fuzz(&issuer)
					issuer.Name = "foo"

					// Test regex with non-empty status.
					issuerData, err := serializeApplyClusterIssuerStatus(&issuer)
					assert.NoError(t, err)
					assert.Regexp(t, expReg, string(issuerData))

					// Test round trip preserves the status.
					var rtIssuer cmapi.ClusterIssuer
					assert.NoError(t, json.Unmarshal(issuerData, &rtIssuer))
					assert.Equal(t, issuer.Status, rtIssuer.Status)

					// String match on empty status.
					issuer.Status = cmapi.IssuerStatus{}
					issuerData, err = serializeApplyClusterIssuerStatus(&issuer)
					assert.NoError(t, err)
					assert.Equal(t, expEmpty, string(issuerData))

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
