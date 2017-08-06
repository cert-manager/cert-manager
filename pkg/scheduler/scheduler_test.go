package scheduler

import (
	"sync"
	"testing"
	"time"
)

func TestAdd(t *testing.T) {
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
				startTime := time.Now()
				queue := NewScheduledWorkQueue(func(obj interface{}) {
					defer wg.Done()
					durationEarly := test.duration - time.Now().Sub(startTime)
					if durationEarly > 0 {
						t.Errorf("got queue item %.2f seconds too early", float64(durationEarly)/float64(time.Second))
					}
					if obj != test.obj {
						t.Errorf("expected obj '%+v' but got obj '%+v'", test.obj, obj)
					}
				})
				queue.Add(test.obj, test.duration)
			}
		}(test))
	}

	wg.Wait()
}

func TestForget(t *testing.T) {
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
				time.Sleep(test.duration * 2)
			}
		}(test))
	}

	wg.Wait()
}
