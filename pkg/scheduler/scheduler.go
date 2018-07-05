package scheduler

import (
	"time"

	"k8s.io/client-go/util/workqueue"
	k8sClock "k8s.io/utils/clock"
)

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
	// Stop stops processing all items and frees all resources
	Stop()
}

type workItem struct {
	processAt time.Time
	item      interface{}
	// itemAdded is used to signal 'Add' that this workItem has been added to the
	// queue.
	// It is not strictly necessary for regular operation, but is necessary to be
	// able to reliably unit test this package.
	itemAdded chan<- struct{}
}

type scheduledWorkQueue struct {
	clock       k8sClock.Clock
	limiter     workqueue.RateLimiter
	processFunc ProcessFunc

	// These channels control the work loop
	// in provides new items to add to processing, forget provides items to
	// forget, done indicates items that have been procssed and can be removed
	// from processing, and stop stops the entire loop.
	in     chan workItem
	forget chan interface{}
	done   chan interface{}
	stop   chan struct{}

	// pending holds items which are waiting for their time to execute
	// processing holds items that are currently being processed, and thus
	// shouldn't be re-added to 'pending' yet.
	// No locks are needed because the workLoop has exclusive ownership of these maps
	pending    map[interface{}]time.Time
	processing map[interface{}]struct{}
	// nextTime holds a timer for the earliest item in 'pending'. It is
	// recalculated any time 'pending' changes.
	nextTime  k8sClock.Timer
	timerRead bool
}

// NewScheduledWorkQueue will create a new workqueue with the given processFunc
func NewScheduledWorkQueue(processFunc ProcessFunc, limiter workqueue.RateLimiter) ScheduledWorkQueue {
	return newScheduledWorkQueue(k8sClock.RealClock{}, processFunc, limiter)
}

// newScheduledWorkQueue will create a new workqueue with the given processFunc
func newScheduledWorkQueue(clock k8sClock.Clock, processFunc ProcessFunc, limiter workqueue.RateLimiter) ScheduledWorkQueue {
	q := &scheduledWorkQueue{
		clock:       clock,
		limiter:     limiter,
		processFunc: processFunc,

		in:     make(chan workItem),
		done:   make(chan interface{}),
		forget: make(chan interface{}),
		stop:   make(chan struct{}),

		pending:    make(map[interface{}]time.Time),
		processing: make(map[interface{}]struct{}),
		// arbitrarily tick in an hour to avoid a nil timer
		nextTime: clock.NewTimer(1 * time.Hour),
	}
	go q.workLoop()

	return q
}

func (s *scheduledWorkQueue) workLoop() {
	for {
		select {
		case <-s.stop:
			return
		case now := <-s.nextTime.C():
			s.timerRead = true
			for obj, t := range s.pending {
				if t.Before(now) || t.Equal(now) {
					delete(s.pending, obj)
					s.processing[obj] = struct{}{}
					go func(obj interface{}) {
						s.processFunc(obj)
						s.done <- obj
					}(obj)
				}
			}
			// reset is only useful if we haven't drained it yet; this case means
			// it's already drained since we just recv'd on the timer
			s.setNextTime()
		case newItem := <-s.in:
			if _, ok := s.processing[newItem.item]; ok {
				// already processing this, be stingy rather than overeager
				continue
			}
			// if this one's already pending, override it with the new time
			// arbitrarily
			s.pending[newItem.item] = newItem.processAt
			s.setNextTime()
			close(newItem.itemAdded)
		case obj := <-s.forget:
			delete(s.pending, obj)
			s.setNextTime()
		case item := <-s.done:
			for obj := range s.processing {
				if obj == item {
					delete(s.processing, obj)
					s.limiter.Forget(obj)
				}
			}
		}
	}
}

func (s *scheduledWorkQueue) setNextTime() {
	// See the time.Timer.Reset docs for why we stop + drain
	// It's only safe to do stop+drain here if the timer has not yet been read,
	// so use s.timerRead to ensure the timer hasn't been.
	if !s.timerRead && !s.nextTime.Stop() {
		<-s.nextTime.C()
		s.timerRead = true
	}
	var min *time.Time
	for _, t := range s.pending {
		t := t
		if min == nil {
			min = &t
			continue
		}
		if t.Before(*min) {
			min = &t
		}
	}
	if min == nil {
		return
	}
	nextTick := min.Sub(s.clock.Now())
	s.nextTime.Reset(nextTick)
	s.timerRead = false
}

// Add will add an item to this queue, executing the ProcessFunc after the
// Duration has come (since the time Add was called). If an existing Timer for
// obj already exists, the previous timer will be cancelled.
func (s *scheduledWorkQueue) Add(obj interface{}, duration time.Duration) time.Duration {
	delay := s.limiter.When(obj)
	done := make(chan struct{})
	s.in <- workItem{
		processAt: s.clock.Now().Add(delay + duration),
		item:      obj,
		itemAdded: done,
	}
	<-done
	return delay + duration
}

// Forget will cancel the timer for the given object, if the timer exists.
// It will not reset any rate limits for the given object, only a successful completion of that object will.
func (s *scheduledWorkQueue) Forget(obj interface{}) {
	s.forget <- obj
}

func (s *scheduledWorkQueue) Stop() {
	close(s.stop)
}
