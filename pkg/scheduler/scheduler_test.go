/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"time"
)

func TestAdd(t *testing.T) {
	after := newMockAfter()
	afterFunc = after.AfterFunc

	var wg sync.WaitGroup
	type testT struct {
		obj      string
		duration time.Duration
	}
	tests := []testT{
		{"test500", time.Millisecond * 500},
		{"test1000", time.Second * 1},
		{"test3000", time.Second * 3},
	}
	for _, test := range tests {
		wg.Add(1)
		t.Run(test.obj, func(test testT) func(*testing.T) {
			waitSubtest := make(chan struct{})
			return func(t *testing.T) {
				startTime := after.currentTime
				queue := NewScheduledWorkQueue(func(obj interface{}) {
					defer wg.Done()
					durationEarly := test.duration - after.currentTime.Sub(startTime)

					if durationEarly > 0 {
						t.Errorf("got queue item %.2f seconds too early", float64(durationEarly)/float64(time.Second))
					}
					if obj != test.obj {
						t.Errorf("expected obj '%+v' but got obj '%+v'", test.obj, obj)
					}
					waitSubtest <- struct{}{}
				})
				queue.Add(test.obj, test.duration)
				after.warp(test.duration + time.Millisecond)
				<-waitSubtest
			}
		}(test))
	}

	wg.Wait()
}

func TestForget(t *testing.T) {
	after := newMockAfter()
	afterFunc = after.AfterFunc

	var wg sync.WaitGroup
	type testT struct {
		obj      string
		duration time.Duration
	}
	tests := []testT{
		{"test500", time.Millisecond * 500},
		{"test1000", time.Second * 1},
		{"test3000", time.Second * 3},
	}
	for _, test := range tests {
		wg.Add(1)
		t.Run(test.obj, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				defer wg.Done()
				queue := NewScheduledWorkQueue(func(obj interface{}) {
					t.Errorf("scheduled function should never be called")
				})
				queue.Add(test.obj, test.duration)
				queue.Forget(test.obj)
				after.warp(test.duration * 2)
			}
		}(test))
	}

	wg.Wait()
}

// TestConcurrentAdd checks that if we add the same item concurrently, it
// doesn't end up hitting a data-race / leaking a timer.
func TestConcurrentAdd(t *testing.T) {
	after := newMockAfter()
	afterFunc = after.AfterFunc
	var wg sync.WaitGroup
	queue := NewScheduledWorkQueue(func(obj interface{}) {
		t.Fatalf("should not be called, but was called with %v", obj)
	})

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			queue.Add(1, 1*time.Second)
			wg.Done()
		}()
	}
	wg.Wait()

	queue.Forget(1)
	after.warp(5 * time.Second)
}

type timerQueueItem struct {
	f       func()
	t       time.Time
	run     bool
	stopped bool
}

func (tq *timerQueueItem) Stop() bool {
	stopped := tq.stopped
	tq.stopped = true
	return stopped
}

type mockAfter struct {
	lock        *sync.Mutex
	startTime   time.Time
	currentTime time.Time
	queue       []*timerQueueItem
}

func newMockAfter() *mockAfter {
	return &mockAfter{
		queue: make([]*timerQueueItem, 0),
		lock:  &sync.Mutex{},
	}
}

func (m *mockAfter) AfterFunc(d time.Duration, f func()) stoppable {
	m.lock.Lock()
	defer m.lock.Unlock()

	item := &timerQueueItem{
		f: f,
		t: m.currentTime.Add(d),
	}
	m.queue = append(m.queue, item)
	return item
}

func (m *mockAfter) warp(d time.Duration) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.currentTime = m.currentTime.Add(d)
	for _, item := range m.queue {
		if item.run || item.stopped {
			continue
		}

		if item.t.Before(m.currentTime) {
			item.run = true
			go item.f()
		}
	}
}
