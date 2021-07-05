/*
Copyright 2021 The cert-manager Authors.

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

package cainjector

import (
	"fmt"
	"sync"
)

// The CA injector can be in one of the 3 states described
// below. The "Setup" stage is the starting stage and is
// maintained until the DoneSetup() function is called.
// The "FirstReconciliation" starts after the DoneSetup()
// function is called, and indicates that the injector is
// reconciling all objects for the first time. Once each
// created InjectorStateHandle has called DoneRound(), the
// stable "Reconciling" stage is started. During this last
// stage the startup probe should succeed.
type Stage int

const (
	Setup Stage = iota
	FirstReconciliation
	Reconciling
)

// InjectorState describes the state of the injector controller
type InjectorState struct {
	sync.Mutex
	stage Stage

	count int
}

// A InjectorStateHandle is a handle that is created when
// calling Fork() on a InjectorState object. This handle is
// only used to update the InjectorState once (the first time
// DoneRound() is called).
type InjectorStateHandle struct {
	injectorState      *InjectorState
	finishedFirstRound bool
}

func NewInjectorState() *InjectorState {
	return &InjectorState{
		stage: Setup,
		count: 0,
	}
}

// This function updates the InjectorState the first time it
// called. After that first call, all subsequent calls to
// DoneRound() will short circuit and directly return.
func (h *InjectorStateHandle) DoneRound() {
	if h.finishedFirstRound {
		return
	}

	h.finishedFirstRound = true

	h.injectorState.Lock()
	defer h.injectorState.Unlock()

	h.injectorState.count -= 1
}

// This function is called after all InjectorStateHandle objects
// are created.
func (s *InjectorState) DoneSetup() error {
	s.Lock()
	defer s.Unlock()

	if s.stage != Setup {
		return fmt.Errorf("Cannot be called when not in Setup stage.")
	}

	s.stage = FirstReconciliation

	return nil
}

// Create a new handle and update InjectorState, so it will wait
// for DoneRound() to be called on the InjectorStateHandle object.
func (s *InjectorState) Fork() (*InjectorStateHandle, error) {
	s.Lock()
	defer s.Unlock()

	if s.stage != Setup {
		return nil, fmt.Errorf("Cannot be called when not in Setup stage.")
	}

	s.count += 1

	return &InjectorStateHandle{
		injectorState:      s,
		finishedFirstRound: false,
	}, nil
}

// Return the current state of the injector. This function is used
// by the startup probe.
func (s *InjectorState) GetState() Stage {
	s.Lock()
	defer s.Unlock()

	if (s.stage == FirstReconciliation) && (s.count == 0) {
		s.stage = Reconciling
	}

	return s.stage
}
