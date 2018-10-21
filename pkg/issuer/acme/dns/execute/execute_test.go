/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package execute

import (
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"strconv"
	"syscall"
	"testing"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"

	"github.com/stretchr/testify/assert"
)

const scriptContents = `#!/bin/sh

set -e

unset PWD

case "$EXECUTE_PLUGIN_ACTION" in
    present)
        cat <&0
        echo "$(env)" 1>&2
        ;;
    cleanup)
        cat <&0
        echo "$(env)" 1>&2
        ;;
	timeout)
		sleep $(cat <&0)
		;;
    *)
        echo "the value of the environment variable EXECUTE_PLUGIN_ACTION is not recognized"
        exit 1
esac
`

var (
	execBinaryPath string
	execStdin      []byte
)

func TestMain(m *testing.M) {
	execStdin = []byte("Exactly as it meant to be.")

	script, err := ioutil.TempFile("", "cert-manager-exec-test-")
	if err != nil {
		log.Fatalln(err)
	}
	execBinaryPath = script.Name()

	if script.Chmod(0700); err != nil {
		log.Fatalln(err)
	}

	_, err = script.WriteString(scriptContents)
	if err != nil {
		log.Fatalln(err)
	}

	if script.Close(); err != nil {
		log.Println(err)
	}

	status := m.Run()

	if os.Remove(script.Name()); err != nil {
		log.Println(err)
	}

	os.Exit(status)
}

func TestNewDNSProviderValid(t *testing.T) {
	_, err := NewDNSProviderCredentials(path.Base(execBinaryPath), path.Dir(execBinaryPath), execStdin, util.RecursiveNameservers)
	assert.NoError(t, err)
}

func TestExecutePresent(t *testing.T) {
	provider, err := NewDNSProviderCredentials(path.Base(execBinaryPath), path.Dir(execBinaryPath), execStdin, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present("132fds.example.com", "", "123dda=")
	assert.NoError(t, err)
}

func TestExecuteCleanUp(t *testing.T) {
	provider, err := NewDNSProviderCredentials(path.Base(execBinaryPath), path.Dir(execBinaryPath), execStdin, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp("132fds.example.com", "", "123dda=")
	assert.NoError(t, err)
}

func TestExecutePresentExecution(t *testing.T) {
	expectedStdout := "Exactly as it meant to be."
	expectedStderr := "EXECUTE_PLUGIN_ACTION=present\nEXECUTE_PLUGIN_VALUE=sadf23ASDFB\nEXECUTE_PLUGIN_TTL=60\nEXECUTE_PLUGIN_DOMAIN=132fds.example.com\n"
	execEnvs := map[string]string{"EXECUTE_PLUGIN_ACTION": "present",
		"EXECUTE_PLUGIN_DOMAIN": util.UnFqdn("132fds.example.com."),
		"EXECUTE_PLUGIN_VALUE":  "sadf23ASDFB",
		"EXECUTE_PLUGIN_TTL":    strconv.Itoa(60)}

	err, stdout, stderr := execute(execBinaryPath, execEnvs, execStdin, 5)
	assert.NoError(t, err)
	assert.Equal(t, expectedStdout, stdout)
	assert.Equal(t, expectedStderr, stderr)
}

func TestExecuteCleanUpExecution(t *testing.T) {
	expectedStdout := "Exactly as it meant to be."
	expectedStderr := "EXECUTE_PLUGIN_ACTION=present\nEXECUTE_PLUGIN_VALUE=sadf23ASDFB\nEXECUTE_PLUGIN_TTL=60\nEXECUTE_PLUGIN_DOMAIN=132fds.example.com\n"
	execEnvs := map[string]string{"EXECUTE_PLUGIN_ACTION": "present",
		"EXECUTE_PLUGIN_DOMAIN": util.UnFqdn("132fds.example.com."),
		"EXECUTE_PLUGIN_VALUE":  "sadf23ASDFB",
		"EXECUTE_PLUGIN_TTL":    strconv.Itoa(60)}

	err, stdout, stderr := execute(execBinaryPath, execEnvs, execStdin, 5)
	assert.NoError(t, err)
	assert.Equal(t, expectedStdout, stdout)
	assert.Equal(t, expectedStderr, stderr)
}

func TestExecuteTimeout(t *testing.T) {
	execEnvs := map[string]string{"EXECUTE_PLUGIN_ACTION": "timeout",
		"EXECUTE_PLUGIN_DOMAIN": util.UnFqdn("132fds.example.com."),
		"EXECUTE_PLUGIN_VALUE":  "sadf23ASDFB",
		"EXECUTE_PLUGIN_TTL":    strconv.Itoa(60)}

	err, _, _ := execute(execBinaryPath, execEnvs, []byte("5"), 2)
	assert.Contains(t, []syscall.WaitStatus{9, 15}, err.(*exec.ExitError).Sys().(syscall.WaitStatus))
}
