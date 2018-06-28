package scheduler

import (
	"sync"
	"time"

	"k8s.io/client-go/util/workqueue"
)

// For mocking purposes.
// This little bit of wrapping needs to be done becuase go doesn't do
// covariance, but it does coerse *time.Timer into stoppable implicitly if we
// write it out like so.
var afterFunc = func(d time.Duration, f func()) stoppable {
	return time.AfterFunc(d, f)
}

// stoppable is the subset of time.Timer which we use, split out for mocking purposes
type stoppable interface {
	Stop() bool
}

// ProcessFunc is a function to process an item in the work queue.
type ProcessFunc func(interface{})

// ScheduledWorkQueue is an interface to describe a queue that will execute the
// given ProcessFunc with the object given to Add once the time.Duration is up,
// since the time of calling Add. It supports passing in a RateLimiter as well,
// which will add an additional delay to the provided schedule automatically.
type ScheduledWorkQueue interface {
	// Add will add an item to this queue, executing the ProcessFunc after the
	// Duration has come (since the time Add was called). If an existing Timer
	// for obj already exists, the previous timer will be cancelled.
	// It returns the duration it will wait before processing the item, including
	// any additional time added by the rate limiter.
	Add(interface{}, time.Duration) time.Duration
	// Forget will cancel the timer for the given object, if the timer exists.
	Forget(interface{})
}

type scheduledWorkQueue struct {
	limiter     workqueue.RateLimiter
	processFunc ProcessFunc
	work        map[interface{}]stoppable
	workLock    sync.Mutex
}

// NewScheduledWorkQueue will create a new workqueue with the given processFunc
func NewScheduledWorkQueue(processFunc ProcessFunc, limiter workqueue.RateLimiter) ScheduledWorkQueue {
	return &scheduledWorkQueue{limiter, processFunc, make(map[interface{}]stoppable), sync.Mutex{}}
}

// Add will add an item to this queue, executing the ProcessFunc after the
// Duration has come (since the time Add was called). If an existing Timer for
// obj already exists, the previous timer will be cancelled.
func (s *scheduledWorkQueue) Add(obj interface{}, duration time.Duration) time.Duration {
	s.workLock.Lock()
	defer s.workLock.Unlock()
	s.forget(obj)
	delay := s.limiter.When(obj)
	s.work[obj] = afterFunc(duration+delay, func() {
		s.processItem(obj)
	})

	return duration + delay
}

// Forget will cancel the timer for the given object, if the timer exists.
// It will not reset any rate limits for the given object, only a successful completion of that object will.
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

// processItem processes the given item, removes it from the queue, and resets
// its rate limit.
func (s *scheduledWorkQueue) processItem(obj interface{}) {
	// since we don't know how long processFunc will run, don't hold the lock during it.
	// Run it before we've removed the item from the queue so if we race, we race
	// towards being more stingy.
	s.processFunc(obj)

	s.workLock.Lock()
	s.limiter.Forget(obj)
	s.forget(obj)
	s.workLock.Unlock()
}
