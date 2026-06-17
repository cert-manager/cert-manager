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

package controller

import (
	"context"
	"fmt"
	"time"
)

// Builder is used to build controllers that implement the queuingController
// interface
type Builder struct {
	// the root controller context factory. Used to build a component context
	// which is passed when calling Register() on the queueing Controller.
	contextFactory *ContextFactory

	// name is the name for this controller
	name string

	// the actual controller implementation
	impl queueingController

	// runDurationFuncs are a list of functions that will be called every
	// 'duration'
	runDurationFuncs []runDurationFunc
}

// New creates a basic Builder, setting the sync call to the one given
func NewBuilder(controllerctx *ContextFactory, name string) *Builder {
	return &Builder{
		contextFactory: controllerctx,
		name:           name,
	}
}

func (b *Builder) For(ctrl queueingController) *Builder {
	b.impl = ctrl
	return b
}

// With will register an additional function that should be called every
// 'duration' alongside the controller.
// This is useful if a controller needs to periodically run a scheduled task.
func (b *Builder) With(function func(context.Context), duration time.Duration) *Builder {
	b.runDurationFuncs = append(b.runDurationFuncs, runDurationFunc{
		fn:       function,
		duration: duration,
	})
	return b
}

func (b *Builder) Complete() (Interface, error) {
	controllerctx, err := b.contextFactory.Build(b.name)
	if err != nil {
		return nil, err
	}

	if b.impl == nil {
		return nil, fmt.Errorf("controller implementation must be non-nil")
	}
	queue, mustSync, err := b.impl.Register(controllerctx)
	if err != nil {
		return nil, fmt.Errorf("error registering controller: %v", err)
	}

	return NewController(b.name, controllerctx.Metrics, b.impl.ProcessItem, mustSync, b.runDurationFuncs, queue), nil
}
