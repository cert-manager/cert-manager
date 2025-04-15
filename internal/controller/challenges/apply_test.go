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

package challenges

import (
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

func Test_serializeApply(t *testing.T) {
	const (
		expReg  = `^{"kind":"Challenge","apiVersion":"acme.cert-manager.io/v1","metadata":{.*},"spec":{.*},"status":{"processing":false,"presented":false}}$`
		numJobs = 10000
	)

	var wg sync.WaitGroup
	jobs := make(chan int)

	wg.Add(numJobs)
	for range 3 {
		go func() {
			for j := range jobs {
				t.Run("fuzz_"+strconv.Itoa(j), func(t *testing.T) {
					var challenge cmacme.Challenge
					fuzz.New().NilChance(0.5).Funcs(
						func(challenge *cmacme.Challenge, c fuzz.Continue) {
							if challenge.Spec.Solver.DNS01 != nil && challenge.Spec.Solver.DNS01.Webhook != nil {
								// Config can only hold data which originates from proper JSON.
								challenge.Spec.Solver.DNS01.Webhook.Config = &apiextensionsv1.JSON{Raw: []byte(`{"some": {"json": "test"}, "string": 42}`)}
							}
						},
					).Fuzz(&challenge)

					// Test regex with non-empty status.
					challengeData, err := serializeApply(&challenge)
					assert.NoError(t, err, "%+#v", challenge)
					assert.Regexp(t, expReg, string(challengeData))

					// Test a roundtrip results in the same data.
					var rtChallenge cmacme.Challenge
					assert.NoError(t, json.Unmarshal(challengeData, &rtChallenge))
					assert.Equal(t, challenge.Spec, rtChallenge.Spec)

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

func Test_serializeApplyStatus(t *testing.T) {
	const (
		expReg   = `^{"kind":"Challenge","apiVersion":"acme.cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{"url":"","authorizationURL":"","dnsName":"","wildcard":false,"type":"","token":"","key":"","solver":{},"issuerRef":{"name":""}},"status":{.*}$`
		expEmpty = `{"kind":"Challenge","apiVersion":"acme.cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{"url":"","authorizationURL":"","dnsName":"","wildcard":false,"type":"","token":"","key":"","solver":{},"issuerRef":{"name":""}},"status":{"processing":false,"presented":false}}`
		numJobs  = 10000
	)

	var wg sync.WaitGroup
	jobs := make(chan int)

	wg.Add(numJobs)
	for range 3 {
		go func() {
			for j := range jobs {
				t.Run("fuzz_"+strconv.Itoa(j), func(t *testing.T) {
					var challenge cmacme.Challenge
					fuzz.New().NilChance(0.5).Fuzz(&challenge)
					challenge.Name = "foo"
					challenge.Namespace = "bar"

					// Test regex with non-empty status.
					challengeData, err := serializeApplyStatus(&challenge)
					assert.NoError(t, err)
					assert.Regexp(t, expReg, string(challengeData))

					// String match on empty status.
					challenge.Status = cmacme.ChallengeStatus{}
					challengeData, err = serializeApplyStatus(&challenge)
					assert.NoError(t, err)
					assert.Equal(t, expEmpty, string(challengeData))

					// Test a roundtrip results in the same data.
					var rtChallenge cmacme.Challenge
					assert.NoError(t, json.Unmarshal(challengeData, &rtChallenge))
					assert.Equal(t, challenge.Status, rtChallenge.Status)

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
