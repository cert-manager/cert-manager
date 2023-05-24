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

package deny

import (
	"testing"
)

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		args            []string
		reason, message string
		expErr          bool
		expErrMsg       string
	}{
		"CR name not passed as arg throws error": {
			args:      []string{},
			reason:    "",
			message:   "",
			expErr:    true,
			expErrMsg: "the name of the CertificateRequest to deny has to be provided as an argument",
		},
		"multiple CR names passed as arg throws error": {
			args:      []string{"cr-1", "cr-1"},
			reason:    "",
			message:   "",
			expErr:    true,
			expErrMsg: "only one argument can be passed: the name of the CertificateRequest",
		},
		"empty reason given should throw error": {
			args:      []string{"cr-1"},
			reason:    "",
			message:   "",
			expErr:    true,
			expErrMsg: "a reason must be given as to who denied this CertificateRequest",
		},
		"empty message given should throw error": {
			args:      []string{"cr-1"},
			reason:    "foo",
			message:   "",
			expErr:    true,
			expErrMsg: "a message must be given as to why this CertificateRequest is denied",
		},
		"all fields populated should not error": {
			args:    []string{"cr-1"},
			reason:  "foo",
			message: "bar",
			expErr:  false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			opts := &Options{
				Reason:  test.reason,
				Message: test.message,
			}

			// Validating args and flags
			err := opts.Validate(test.args)
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v",
					test.expErr, err)
			}
			if err != nil && err.Error() != test.expErrMsg {
				t.Errorf("got unexpected error when validating args and flags, expected: %v; actual: %v", test.expErrMsg, err)
			}
		})
	}
}
