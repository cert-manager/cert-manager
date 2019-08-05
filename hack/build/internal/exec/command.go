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

package exec

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
)

// Run will execute the cmd and return readers for both stdout and stderr.
// If out is provided, stdout and stderr will both be written to out.
// It also returns an stdout and stderr io.Reader that can be used by callers
// to read command output.
func Run(out io.Writer, cmd *exec.Cmd) (stdout, stderr io.Reader, err error) {
	var stdoutRW, stderrRW io.ReadWriter

	stdoutRW = &bytes.Buffer{}
	stderrRW = &bytes.Buffer{}
	stdoutW := stdoutRW.(io.Writer)
	stderrW := stderrRW.(io.Writer)
	if out != nil {
		stdoutW = io.MultiWriter(stdoutW, out)
		stderrW = io.MultiWriter(stderrW, out)
	}

	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	return stdoutRW, stderrRW, cmd.Run()
}

// RunCommand will execute the given cmd with the provided args.
// If out is provided, stdout and stderr will both be written to out.
// It also returns an stdout and stderr io.Reader that can be used by callers
// to read command output.
func RunCommand(out io.Writer, cmd string, args ...string) (stdout, stderr io.Reader, err error) {
	return Run(out, exec.Command(cmd, args...))
}

// FormatError can be used to annotate errors returned from Run using the
// stderr of the command to provide extra context.
func FormatError(stdout, stderr io.Reader, err error) error {
	if err == nil {
		return nil
	}
	// if err != nil, we read all of stderr and append the output to the error
	errText, readErr := ioutil.ReadAll(stderr)
	if readErr != nil {
		// this shouldn't really occur
		return fmt.Errorf("error reading stderr whilst handling command error (%v): %v", err, readErr)
	}
	if len(errText) == 0 {
		return fmt.Errorf("failed to execute command: %v", err)
	}

	return fmt.Errorf("failed to execute command: %v, output: \n%v", err, string(errText))
}
