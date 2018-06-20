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
	startTime   time.Time
	currentTime time.Time
	queue       []*timerQueueItem
}

func newMockAfter() *mockAfter {
	return &mockAfter{
		queue: make([]*timerQueueItem, 0),
	}
}

func (m *mockAfter) AfterFunc(d time.Duration, f func()) stoppable {
	item := &timerQueueItem{
		f: f,
		t: m.currentTime.Add(d),
	}
	m.queue = append(m.queue, item)
	return item
}

func (m *mockAfter) warp(d time.Duration) {
	m.currentTime = m.currentTime.Add(d)
	for _, item := range m.queue {
		if item.run || item.stopped {
			continue
		}

		if item.t.Before(m.currentTime) {
			item.run = true
			go func(f func()) {
				f()
			}(item.f)
		}
	}
}
