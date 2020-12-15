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
	"time"

	"k8s.io/utils/clock"
)

// For mocking purposes.
// This little bit of wrapping needs to be done because go doesn't do
// covariance, but it does coerce *time.Timer into stoppable implicitly if we
// write it out like so.
var afterFunc = func(c clock.Clock, d time.Duration, f func()) stoppable {
	t := c.NewTimer(d)

	go func() {
		defer t.Stop()
		if ti := <-t.C(); ti == (time.Time{}) {
			return
		}
		f()
	}()

	return t
}

// stoppable is the subset of time.Timer which we use, split out for mocking purposes
type stoppable interface {
	Stop() bool
}

// ProcessFunc is a function to process an item in the work queue.
type ProcessFunc func(interface{})

// ScheduledWorkQueue is an interface to describe a queue that will execute the
// given ProcessFunc with the object given to Add once the time.Duration is up,
// since the time of calling Add.
type ScheduledWorkQueue interface {
	// Add will add an item to this queue, executing the ProcessFunc after the
	// Duration has come (since the time Add was called). If an existing Timer
	// for obj already exists, the previous timer will be cancelled.
	Add(interface{}, time.Duration)
	// Forget will cancel the timer for the given object, if the timer exists.
	Forget(interface{})
}

type scheduledWorkQueue struct {
	processFunc ProcessFunc
	clock       clock.Clock
	work        map[interface{}]stoppable
	workLock    sync.Mutex
}

// NewScheduledWorkQueue will create a new workqueue with the given processFunc
func NewScheduledWorkQueue(clock clock.Clock, processFunc ProcessFunc) ScheduledWorkQueue {
	return &scheduledWorkQueue{
		processFunc: processFunc,
		clock:       clock,
		work:        make(map[interface{}]stoppable),
		workLock:    sync.Mutex{},
	}
}

// Add will add an item to this queue, executing the ProcessFunc after the
// Duration has come (since the time Add was called). If an existing Timer for
// obj already exists, the previous timer will be cancelled.
func (s *scheduledWorkQueue) Add(obj interface{}, duration time.Duration) {
	s.workLock.Lock()
	defer s.workLock.Unlock()
	s.forget(obj)
	s.work[obj] = afterFunc(s.clock, duration, func() {
		defer s.Forget(obj)
		s.processFunc(obj)
	})
}

// Forget will cancel the timer for the given object, if the timer exists.
func (s *scheduledWorkQueue) Forget(obj interface{}) {
	s.workLock.Lock()
	defer s.workLock.Unlock()
	s.forget(obj)
}

// forget cancels and removes an item. It *must* be called with the lock already held
func (s *scheduledWorkQueue) forget(obj interface{}) {
	if timer, ok := s.work[obj]; ok {
		timer.Stop()
		delete(s.work, obj)
	}
}
