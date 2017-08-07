package scheduler

import (
	"sync"
	"time"
)

type ProcessFunc func(interface{})

type ScheduledWorkQueue interface {
	Add(interface{}, time.Duration)
	Forget(interface{})
}

type scheduledWorkQueue struct {
	processFunc ProcessFunc
	work        map[interface{}]*time.Timer
	workLock    sync.Mutex
}

func NewScheduledWorkQueue(processFunc ProcessFunc) ScheduledWorkQueue {
	return &scheduledWorkQueue{processFunc, make(map[interface{}]*time.Timer), sync.Mutex{}}
}

func (s *scheduledWorkQueue) Add(obj interface{}, duration time.Duration) {
	s.clearTimer(obj)
	s.work[obj] = time.AfterFunc(duration, func() {
		defer s.clearTimer(obj)
		s.processFunc(obj)
	})
}

func (s *scheduledWorkQueue) Forget(obj interface{}) {
	s.clearTimer(obj)
}

func (s *scheduledWorkQueue) clearTimer(obj interface{}) {
	s.workLock.Lock()
	defer s.workLock.Unlock()
	if timer, ok := s.work[obj]; ok {
		timer.Stop()
		delete(s.work, obj)
	}
}
