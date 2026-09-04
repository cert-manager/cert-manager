/*
Copyright 2026 The cert-manager Authors.

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
	"sync"
	"testing"
	"time"

	"k8s.io/utils/clock"
	fakeclock "k8s.io/utils/clock/testing"
)

func TestClockConcurrentSetAndRead(t *testing.T) {
	t.Cleanup(func() { SetClock(clock.RealClock{}) })

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			SetClock(fakeclock.NewFakeClock(time.Unix(int64(i), 0)))
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = Clock.Now()
			_ = Clock.Since(time.Unix(0, 0))
		}
	}()

	wg.Wait()
}

func TestSetClockNilDefaultsToRealClock(t *testing.T) {
	t.Cleanup(func() { SetClock(clock.RealClock{}) })

	SetClock(nil)
	_ = Clock.Now()
	_ = Clock.Since(time.Unix(0, 0))
}
