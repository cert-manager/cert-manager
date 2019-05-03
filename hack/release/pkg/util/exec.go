/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"fmt"
	"os"
	"os/exec"

	"github.com/go-logr/logr"
	logf "github.com/jetstack/cert-manager/hack/release/pkg/log"
)

func RunE(log logr.Logger, cmd *exec.Cmd) error {
	// debug mode logs directly to stdout/stderr
	if log.V(logf.LogLevelTrace).Enabled() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		log = log.WithValues("command", append([]string{cmd.Path}, cmd.Args[1:]...))
		log.V(logf.LogLevelDebug).Info("executing command with default stdout/stderr")
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to execute command: %v", err)
		}

		return nil
	}

	_, err := RunPrintCombined(log, cmd)
	return err
}

// RunPrintCombined will run the given command, capturing its output using CombinedOutput.
// If the command execution fails, the command output will be logged to the loggers
// underlying output Writer.
// This function will return the combined output bytes on both failure and success.
func RunPrintCombined(log logr.Logger, cmd *exec.Cmd) ([]byte, error) {
	log = log.WithValues("command", append([]string{cmd.Path}, cmd.Args[1:]...))
	log.V(logf.LogLevelDebug).Info("executing command")

	out, err := cmd.CombinedOutput()
	if err != nil {
		logf.Output.Write(out)
		if len(out) == 0 {
			logf.Output.Write([]byte("(no output)"))
		}
		return out, fmt.Errorf("failed to execute command: %v", err)
	}
	return out, nil
}
