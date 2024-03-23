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

package util

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var onlyOneSignalHandler = make(chan struct{})
var errorExitCodeChannel = make(chan int, 1)

// ExitBehavior controls how the program should be terminated
// in response to a shutdown signal.
type ExitBehavior int

const (
	// AlwaysErrCode indicates the exit code of the program should always be nonzero
	// and should correspond to the numeric value of the signal that was received.
	AlwaysErrCode ExitBehavior = iota

	// GracefulShutdown treats a shutdown signal as a request to exit gracefully, terminating
	// goroutines and returning an exit code of 0 if there are no errors during shutdown.
	GracefulShutdown ExitBehavior = iota
)

// SetupExitHandler:
// A context is returned which is canceled on receiving a shutdown signal (SIGTERM
// or SIGINT). If a second signal is caught, the program is terminated directly with
// exit code 130.
// SetupExitHandler also returns an exit function, this exit function calls os.Exit(...)
// if there is a exit code in the errorExitCodeChannel.
// The errorExitCodeChannel receives exit codes when SetExitCode is called or when
// a shutdown signal is received (only if exitBehavior is AlwaysErrCode).
func SetupExitHandler(parentCtx context.Context, exitBehavior ExitBehavior) (context.Context, func()) {
	close(onlyOneSignalHandler) // panics when called twice

	ctx, cancel := context.WithCancelCause(parentCtx)
	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		// first signal. Cancel context and pass exit code to errorExitCodeChannel.
		signalInt := int((<-c).(syscall.Signal))
		if exitBehavior == AlwaysErrCode {
			errorExitCodeChannel <- (128 + signalInt)
		}
		cancel(fmt.Errorf("received signal %d", signalInt))
		// second signal. Exit directly.
		<-c
		os.Exit(130)
	}()

	return ctx, func() {
		select {
		case signalInt := <-errorExitCodeChannel:
			os.Exit(signalInt)
		default:
			// Do not exit, there are no exit codes in the channel,
			// so just continue and let the main function go out of
			// scope instead.
		}
	}
}
