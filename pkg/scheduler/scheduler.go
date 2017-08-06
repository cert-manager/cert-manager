package scheduler

import (
	"sync"
	"time"
)

type ProcessFunc func(interface{})

type ScheduledWorkQueue struct {
	processFunc ProcessFunc
	work        map[interface{}]*time.Timer
	workLock    sync.Mutex
}

func NewScheduledWorkQueue(processFunc ProcessFunc) *ScheduledWorkQueue {
	return &ScheduledWorkQueue{processFunc, make(map[interface{}]*time.Timer), sync.Mutex{}}
}

func (s *ScheduledWorkQueue) Add(obj interface{}, duration time.Duration) {
	s.clearTimer(obj)
	s.work[obj] = time.AfterFunc(duration, func() {
		defer s.clearTimer(obj)
		s.processFunc(obj)
	})
}

func (s *ScheduledWorkQueue) Forget(obj interface{}) {
	s.clearTimer(obj)
}

func (s *ScheduledWorkQueue) clearTimer(obj interface{}) {
	s.workLock.Lock()
	defer s.workLock.Unlock()
	if timer, ok := s.work[obj]; ok {
		timer.Stop()
		delete(s.work, obj)
	}
}
