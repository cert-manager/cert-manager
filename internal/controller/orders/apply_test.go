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

package orders

import (
	"strconv"
	"sync"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
)

func Test_serializeApplyStatus(t *testing.T) {
	const (
		expReg   = `^{"kind":"Order","apiVersion":"acme.cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{"request":null,"issuerRef":{"name":""}},"status":{.*}$`
		expEmpty = `{"kind":"Order","apiVersion":"acme.cert-manager.io/v1","metadata":{"name":"foo","namespace":"bar","creationTimestamp":null},"spec":{"request":null,"issuerRef":{"name":""}},"status":{}}`
		numJobs  = 10000
	)

	var wg sync.WaitGroup
	jobs := make(chan int)

	wg.Add(numJobs)
	for i := 0; i < 3; i++ {
		go func() {
			for j := range jobs {
				t.Run("fuzz_"+strconv.Itoa(j), func(t *testing.T) {
					var order cmacme.Order
					fuzz.New().NilChance(0.5).Fuzz(&order)
					order.Name = "foo"
					order.Namespace = "bar"

					// Test regex with non-empty status.
					orderData, err := serializeApplyStatus(&order)
					assert.NoError(t, err)
					assert.Regexp(t, expReg, string(orderData))

					// String match on empty status.
					order.Status = cmacme.OrderStatus{}
					orderData, err = serializeApplyStatus(&order)
					assert.NoError(t, err)
					assert.Equal(t, expEmpty, string(orderData))

					wg.Done()
				})
			}
		}()
	}

	for i := 0; i < numJobs; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}
