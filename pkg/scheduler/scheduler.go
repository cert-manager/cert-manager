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

// We are writing our own time.AfterFunc to be able to mock the clock. The
// cancel function can be called concurrently.
func afterFunc(c clock.Clock, d time.Duration, f func()) (cancel func()) {
	t := c.NewTimer(d)
	cancelCh := make(chan struct{})
	cancelOnce := sync.Once{}
	cancel = func() {
		t.Stop()
		cancelOnce.Do(func() {
			close(cancelCh)
		})
	}

	go func() {
		defer cancel()

		select {
		case <-t.C():
			// We don't need to check whether the channel has returned a zero
			// value since t.C is never closed as per the timer.Stop
			// documentation.
			f()
		case <-cancelCh:
			return
		}
	}()

	return cancel
}

// ProcessFunc is a function to process an item in the work queue.
type ProcessFunc[T comparable] func(T)

// ScheduledWorkQueue is an interface to describe a queue that will execute the
// given ProcessFunc with the object given to Add once the time.Duration is up,
// since the time of calling Add.
type ScheduledWorkQueue[T comparable] interface {
	// Add will add an item to this queue, executing the ProcessFunc after the
	// Duration has come (since the time Add was called). If an existing Timer
	// for obj already exists, the previous timer will be cancelled.
	Add(T, time.Duration)

	// Forget will cancel the timer for the given object, if the timer exists.
	Forget(T)
}

type scheduledWorkQueue[T comparable] struct {
	processFunc ProcessFunc[T]
	clock       clock.Clock
	work        map[T]func()
	workLock    sync.Mutex

	// Testing purposes.
	afterFunc func(clock.Clock, time.Duration, func()) func()
}

// NewScheduledWorkQueue will create a new workqueue with the given processFunc
func NewScheduledWorkQueue[T comparable](clock clock.Clock, processFunc ProcessFunc[T]) ScheduledWorkQueue[T] {
	return &scheduledWorkQueue[T]{
		processFunc: processFunc,
		clock:       clock,
		work:        make(map[T]func()),
		workLock:    sync.Mutex{},

		afterFunc: afterFunc,
	}
}

// Add will add an item to this queue, executing the ProcessFunc after the
// Duration has come (since the time Add was called). If an existing Timer for
// obj already exists, the previous timer will be cancelled.
func (s *scheduledWorkQueue[T]) Add(obj T, duration time.Duration) {
	s.workLock.Lock()
	defer s.workLock.Unlock()

	if cancel, ok := s.work[obj]; ok {
		cancel()
		delete(s.work, obj)
	}

	s.work[obj] = afterFunc(s.clock, duration, func() {
		defer s.Forget(obj)
		s.processFunc(obj)
	})
}

// Forget will cancel the timer for the given object, if the timer exists.
func (s *scheduledWorkQueue[T]) Forget(obj T) {
	s.workLock.Lock()
	defer s.workLock.Unlock()

	if cancel, ok := s.work[obj]; ok {
		cancel()
		delete(s.work, obj)
	}
}
