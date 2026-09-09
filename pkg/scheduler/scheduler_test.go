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

package scheduler

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/clock"
)

func TestAdd(t *testing.T) {
	for _, d := range []time.Duration{500 * time.Millisecond, time.Second, 3 * time.Second} {
		t.Run(d.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				var mu sync.Mutex
				var firedAt time.Time
				queue := NewScheduledWorkQueue(clock.RealClock{}, func(obj string) {
					mu.Lock()
					defer mu.Unlock()
					firedAt = time.Now()
				})
				queue.Add("obj", d)

				time.Sleep(d - time.Nanosecond)
				synctest.Wait()
				mu.Lock()
				assert.True(t, firedAt.IsZero(), "fired early")
				mu.Unlock()

				time.Sleep(time.Nanosecond)
				synctest.Wait()
				mu.Lock()
				assert.Equal(t, start.Add(d), firedAt)
				mu.Unlock()
			})
		})
	}
}

func TestForget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := NewScheduledWorkQueue(clock.RealClock{}, func(string) {
			t.Error("scheduled function should never be called")
		})
		queue.Add("obj", time.Second)
		queue.Forget("obj")
		time.Sleep(time.Hour)
		synctest.Wait()
		// synctest.Test also fails if the afterFunc goroutine is still parked when this returns.
	})
}

func TestAfterFuncStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 10000 {
			cancel := afterFunc(clock.RealClock{}, time.Hour, func() { t.Error("should never be called") })
			cancel()
		}
	})
}

// TestConcurrentAdd checks that if we add the same item concurrently, it
// doesn't end up hitting a data-race / leaking a timer.
func TestConcurrentAdd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wg sync.WaitGroup
		queue := NewScheduledWorkQueue(clock.RealClock{}, func(obj int) {
			t.Errorf("should not be called, but was called with %v", obj)
		})

		for range 1000 {
			wg.Go(func() {
				queue.Add(1, 1*time.Second)
			})
		}
		wg.Wait()

		queue.Forget(1)
		time.Sleep(5 * time.Second)
		synctest.Wait()
	})
}

// TestAddDuringCallbackKeepsNewerTimer reproduces #9269: a newer Add for
// the same object must not be cancelled by the fired timer's deferred
// cleanup.
func TestAddDuringCallbackKeepsNewerTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var calls []string

		release := make(chan struct{})
		queue := NewScheduledWorkQueue(clock.RealClock{}, func(obj string) {
			mu.Lock()
			first := len(calls) == 0
			mu.Unlock()
			if first {
				// Hold the callback open so the map entry can be replaced
				// while the fired timer's cleanup is still pending.
				<-release
			}
			mu.Lock()
			calls = append(calls, obj)
			mu.Unlock()
		})

		queue.Add("obj", time.Second)

		time.Sleep(time.Second)
		synctest.Wait() // timer fired; callback is now blocked on release

		queue.Add("obj", time.Minute) // replaces the entry
		close(release)
		synctest.Wait() // the first callback's cleanup has run
		assert.Len(t, queue.(*scheduledWorkQueue[string]).work, 1)

		time.Sleep(time.Minute)
		synctest.Wait()

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"obj", "obj"}, calls)
		assert.Empty(t, queue.(*scheduledWorkQueue[string]).work)
	})
}
