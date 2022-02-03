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

package ctl

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/cert-manager/cert-manager/cmd/ctl/cmd"
	"github.com/cert-manager/cert-manager/test/integration/ctl/install_framework"
	"github.com/cert-manager/cert-manager/test/internal/util"
)

func TestCtlInstall(t *testing.T) {
	tests := map[string]struct {
		prerun       bool
		preInputArgs []string
		preExpErr    bool
		preExpOutput string

		inputArgs []string
		expErr    bool
		expOutput string
	}{
		"install cert-manager": {
			inputArgs: []string{},
			expErr:    false,
			expOutput: `STATUS: deployed`,
		},
		"install cert-manager (already installed)": {
			prerun:       true,
			preInputArgs: []string{},
			preExpErr:    false,
			preExpOutput: `STATUS: deployed`,

			inputArgs: []string{},
			expErr:    true,
			expOutput: `^Found existing installed cert-manager CRDs! Cannot continue with installation.$`,
		},
		"install cert-manager (already installed, in other namespace)": {
			prerun:       true,
			preInputArgs: []string{"--namespace=test"},
			preExpErr:    false,
			preExpOutput: `STATUS: deployed`,

			inputArgs: []string{},
			expErr:    true,
			expOutput: `^Found existing installed cert-manager CRDs! Cannot continue with installation.$`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			testApiServer, cleanup := install_framework.NewTestInstallApiServer(t)
			defer cleanup()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
			defer cancel()

			if test.prerun {
				executeCommandAndCheckOutput(t, ctx, testApiServer.KubeConfig(), test.preInputArgs, test.preExpErr, test.preExpOutput)
			}

			executeCommandAndCheckOutput(t, ctx, testApiServer.KubeConfig(), test.inputArgs, test.expErr, test.expOutput)
		})
	}
}

func executeCommandAndCheckOutput(
	t *testing.T,
	ctx context.Context,
	kubeConfig string,
	inputArgs []string,
	expErr bool,
	expOutput string,
) {
	// Options to run status command
	stdin := bytes.NewBufferString("")
	stdout := bytes.NewBufferString("")

	chartPath := util.GetTestPath("deploy", "charts", "cert-manager", "cert-manager.tgz")
	cmd := cmd.NewCertManagerCtlCommand(ctx, stdin, stdout, stdout)
	cmd.SetArgs(append([]string{
		fmt.Sprintf("--kubeconfig=%s", kubeConfig),
		"--wait=false",
		fmt.Sprintf("--chart-name=%s", chartPath),
		"x",
		"install",
	}, inputArgs...))

	err := cmd.Execute()
	if err != nil {
		fmt.Fprintf(stdout, "%s\n", err)

		if !expErr {
			t.Errorf("got unexpected error: %v", err)
		} else {
			t.Logf("got an error, which was expected, details: %v", err)
		}
	} else if expErr {
		// expected error but error is nil
		t.Errorf("expected but got no error")
	}

	match, err := regexp.MatchString(strings.TrimSpace(expOutput), strings.TrimSpace(stdout.String()))
	if err != nil {
		t.Error(err)
	}
	dmp := diffmatchpatch.New()
	if !match {
		diffs := dmp.DiffMain(strings.TrimSpace(expOutput), strings.TrimSpace(stdout.String()), false)
		t.Errorf(
			"got unexpected output, diff (ignoring line anchors ^ and $ and regex for creation time):\n"+
				"diff: %s\n\n"+
				" exp: %s\n\n"+
				" got: %s",
			dmp.DiffPrettyText(diffs),
			expOutput,
			stdout.String(),
		)
	}
}
