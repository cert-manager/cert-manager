package controller

// This file defines types for controllers to register themselves with the
// controller package.

// Interface represents a controller that can run. 'workers' should be the
// number of independent goroutines for this controller in question that
// are to be run, and the workers should shut down upon a signal on stopCh.
// This method should block until all workers have exited cleanly, thus
// allowing for graceful shutdown of control loops.
type Interface func(workers int, stopCh <-chan struct{}) error

// Constructor is a function that creates a new control loop given a
// controller Context.
type Constructor func(ctx *Context) Interface

var (
	known = make(map[string]Constructor, 0)
)

// Known returns a map of the registered controller Constructors
func Known() map[string]Constructor {
	return known
}

// Register registers a controller constructor with the controller package
func Register(name string, fn Constructor) {
	known[name] = fn
}
