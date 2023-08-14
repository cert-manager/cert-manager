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

package v1alpha1

import (
	"reflect"
	"testing"

	logsapi "k8s.io/component-base/logs/api/v1"

	"k8s.io/component-base/logs"
)

func TestConvert_Pointer_v1_LoggingConfiguration_To_v1_LoggingConfiguration(t *testing.T) {

	testInput := logs.NewOptions()
	generalInput := &testInput
	var nilTestInput *logsapi.LoggingConfiguration = nil
	var nilInput = &nilTestInput

	testcases := map[string]struct {
		in       **logsapi.LoggingConfiguration
		expected logsapi.LoggingConfiguration
	}{
		"general case ": {
			in:       generalInput,
			expected: *logs.NewOptions(),
		},
		"nil case": {
			in:       nilInput,
			expected: *logs.NewOptions(),
		},
	}
	for testName, testcase := range testcases {

		out := logsapi.LoggingConfiguration{}
		Convert_Pointer_v1_LoggingConfiguration_To_v1_LoggingConfiguration(testcase.in, &out, nil)
		if !reflect.DeepEqual(testcase.expected, out) {
			t.Errorf("\"%s\": expected \n\t%#v, got \n\t%#v\n", testName, testcase.expected, out)
		}
		if *testcase.in != nil && *testcase.in == &out {
			t.Errorf("\"%s\": expected input and output to have different pointers, but they are the same.\n", testName)
		}
	}
}

func Test_Convert_v1_LoggingConfiguration_To_Pointer_v1_LoggingConfiguration(t *testing.T) {
	testcases := map[string]struct {
		in       *logsapi.LoggingConfiguration
		expected *logsapi.LoggingConfiguration
	}{
		"general case ": {
			in:       logs.NewOptions(),
			expected: logs.NewOptions(),
		},
	}

	for testName, testcase := range testcases {
		temp := &logsapi.LoggingConfiguration{}
		out := &temp
		Convert_v1_LoggingConfiguration_To_Pointer_v1_LoggingConfiguration(testcase.in, out, nil)
		if !reflect.DeepEqual(testcase.expected, *out) {
			t.Errorf("\"%s\": expected \n\t%#v, got \n\t%#v\n", testName, testcase.expected, out)
		}

	}

}
