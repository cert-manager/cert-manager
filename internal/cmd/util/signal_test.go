//go:build !windows

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

package util

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// based on https://go.dev/talks/2014/testing.slide#23 and
// https://stackoverflow.com/a/33404435
func testExitCode(
	t *testing.T,
	fn func(t *testing.T),
) int {
	if os.Getenv("BE_CRASHER") == "1" {
		fn(t)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run="+t.Name())
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()

	if e, ok := err.(*exec.ExitError); ok {
		return e.ExitCode()
	}

	return 0
}

func TestSetupExitHandlerAlwaysErrCodeSIGTERM(t *testing.T) {
	exitCode := testExitCode(t, func(t *testing.T) {
		ctx := context.Background()
		ctx, complete := SetupExitHandler(ctx, AlwaysErrCode)
		defer complete()

		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}

		// Wait for the program to shut down.
		<-ctx.Done()

		if context.Cause(ctx).Error() != "received signal 15" {
			t.Errorf("expected signal 15, got %s", ctx.Err().Error())
			os.Exit(99)
		}
	})

	if exitCode != 143 {
		t.Errorf("expected exit code 143, got %d", exitCode)
	}
}

func TestSetupExitHandlerAlwaysErrCodeSIGINT(t *testing.T) {
	exitCode := testExitCode(t, func(t *testing.T) {
		ctx := context.Background()
		ctx, complete := SetupExitHandler(ctx, AlwaysErrCode)
		defer complete()

		if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
			t.Fatal(err)
		}

		// Wait for the program to shut down.
		<-ctx.Done()

		if context.Cause(ctx).Error() != "received signal 2" {
			t.Errorf("expected signal 2, got %s", ctx.Err().Error())
			os.Exit(99)
		}
	})

	if exitCode != 130 {
		t.Errorf("expected exit code 130, got %d", exitCode)
	}
}

func TestSetupExitHandlerGracefulShutdownSIGINT(t *testing.T) {
	exitCode := testExitCode(t, func(t *testing.T) {
		ctx := context.Background()
		ctx, complete := SetupExitHandler(ctx, GracefulShutdown)
		defer complete()

		if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
			t.Fatal(err)
		}

		// Wait for the program to shut down.
		<-ctx.Done()

		if context.Cause(ctx).Error() != "received signal 2" {
			t.Errorf("expected signal 2, got %s", ctx.Err().Error())
			os.Exit(99)
		}
	})

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}
