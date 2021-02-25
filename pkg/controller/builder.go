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

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// Builder is used to build controllers that implement the queuingController
// interface
type Builder struct {
	// the root controller context, used when calling Register() on
	// the queueingController
	context *Context

	// name is the name for this controller
	name string

	// a reference to the root context for this controller, used
	// as a basis for other contexts and for logging
	ctx context.Context

	// the actual controller implementation
	impl queueingController

	// runFirstFuncs are a list of functions that will be called immediately
	// after the controller has been initialised, once. They are run in queue, sequentially,
	// and block runDurationFuncs until complete.
	runFirstFuncs []runFunc

	// runDurationFuncs are a list of functions that will be called every
	// 'duration'
	runDurationFuncs []runDurationFunc
}

// New creates a basic Builder, setting the sync call to the one given
func NewBuilder(controllerctx *Context, name string) *Builder {
	ctx := logf.NewContext(controllerctx.RootContext, nil, name)
	return &Builder{
		context: controllerctx,
		ctx:     ctx,
		name:    name,
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

// First will register a function that will be called once, after the
// controller has been initialised. They are queued, run sequentially, and
// block "With" runDurationFuncs from running until all are complete.
func (b *Builder) First(function func(context.Context)) *Builder {
	b.runFirstFuncs = append(b.runFirstFuncs, function)
	return b
}

func (b *Builder) Complete() (Interface, error) {
	if b.context == nil {
		return nil, fmt.Errorf("controller context must be non-nil")
	}
	if b.impl == nil {
		return nil, fmt.Errorf("controller implementation must be non-nil")
	}
	queue, mustSync, err := b.impl.Register(b.context)
	if err != nil {
		return nil, fmt.Errorf("error registering controller: %v", err)
	}

	return NewController(b.ctx, b.name, b.context.Metrics, b.impl.ProcessItem, mustSync, b.runDurationFuncs, queue), nil
}
