package scheduler

import (
	"sort"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/util/workqueue"
	fakeclock "k8s.io/utils/clock/testing"
)

func TestAdd(t *testing.T) {
	fc := fakeclock.NewFakeClock(time.Now())

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
				startTime := fc.Now()
				queue := newScheduledWorkQueue(fc, func(obj interface{}) {
					defer wg.Done()
					durationEarly := test.duration - fc.Now().Sub(startTime)

					if durationEarly > 0 {
						t.Errorf("got queue item %.2f seconds too early", float64(durationEarly)/float64(time.Second))
					}
					if obj != test.obj {
						t.Errorf("expected obj '%+v' but got obj '%+v'", test.obj, obj)
					}
					waitSubtest <- struct{}{}
				}, noopRateLimiter{})
				queue.Add(test.obj, test.duration)
				fc.Step(test.duration + time.Millisecond)
				<-waitSubtest
			}
		}(test))
	}

	wg.Wait()
}

func TestNoEarlyRun(t *testing.T) {
	fc := fakeclock.NewFakeClock(time.Now())

	queue := newScheduledWorkQueue(fc, func(obj interface{}) {
		t.Fatalf("should not run but got: %v", obj)
	}, noopRateLimiter{})
	defer queue.Stop()
	queue.Add("500ms", 500*time.Millisecond)
	queue.Add("600ms", 600*time.Millisecond)
	queue.Add("500ms2", 500*time.Millisecond)

	fc.Step(1 * time.Millisecond)
	fc.Step(100 * time.Millisecond)
	fc.Step(200 * time.Millisecond)
}

func TestSameDelayRun(t *testing.T) {
	fc := fakeclock.NewFakeClock(time.Now())

	run := make(chan string)

	queue := newScheduledWorkQueue(fc, func(obj interface{}) {
		run <- obj.(string)
	}, noopRateLimiter{})
	queue.Add("500ms", 500*time.Millisecond)
	queue.Add("500ms2", 500*time.Millisecond)
	queue.Add("600ms", 600*time.Millisecond)

	fc.Step(501 * time.Millisecond)
	gotten := []string{<-run, <-run}
	sort.Strings(gotten)
	if gotten[0] != "500ms" || gotten[1] != "500ms2" {
		t.Errorf("expected to get 500ms, 500ms2, got %v", gotten)
	}

	fc.Step(100 * time.Millisecond)
	if gotten := <-run; gotten != "600ms" {
		t.Errorf("expected 600ms, got %v", gotten)
	}
}

func TestForget(t *testing.T) {
	fc := fakeclock.NewFakeClock(time.Now())

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
				queue := newScheduledWorkQueue(fc, func(obj interface{}) {
					t.Errorf("scheduled function should never be called")
				}, noopRateLimiter{})
				queue.Add(test.obj, test.duration)
				queue.Forget(test.obj)
				fc.Step(test.duration * 2)
			}
		}(test))
	}

	wg.Wait()
}

// TestConcurrentAdd checks that if we add the same item concurrently, it
// doesn't end up hitting a data-race / leaking a timer.
func TestConcurrentAdd(t *testing.T) {
	fc := fakeclock.NewFakeClock(time.Now())

	var wg sync.WaitGroup
	queue := newScheduledWorkQueue(fc, func(obj interface{}) {
		t.Fatalf("should not be called, but was called with %v", obj)
	}, noopRateLimiter{})

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			queue.Add(1, 1*time.Second)
			wg.Done()
		}()
	}
	wg.Wait()

	queue.Forget(1)
	fc.Step(5 * time.Second)
}

type noopRateLimiter struct{}

var _ workqueue.RateLimiter = noopRateLimiter{}

func (noopRateLimiter) When(item interface{}) time.Duration {
	return 0
}
func (noopRateLimiter) Forget(item interface{}) {}
func (noopRateLimiter) NumRequeues(item interface{}) int {
	return 0
}
