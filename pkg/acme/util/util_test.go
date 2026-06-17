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
	"net/http"
	"testing"
	"time"
)

func TestRetryBackoff(t *testing.T) {
	type args struct {
		n    int
		r    *http.Request
		resp *http.Response
	}
	tests := []struct {
		name           string
		args           args
		validateOutput func(time.Duration) bool
	}{
		{
			name: "Do not retry a non 400 error",
			args: args{
				n:    0,
				r:    &http.Request{},
				resp: &http.Response{StatusCode: http.StatusUnauthorized},
			},
			validateOutput: func(duration time.Duration) bool {
				return duration == -1
			},
		},
		{
			name: "Retry a 400 error when the first time",
			args: args{
				n:    0,
				r:    &http.Request{},
				resp: &http.Response{StatusCode: http.StatusBadRequest},
			},
			validateOutput: func(duration time.Duration) bool {
				return duration > 0
			},
		},
		{
			name: "Retry a 400 error when less than 6 times",
			args: args{
				n:    5,
				r:    &http.Request{},
				resp: &http.Response{StatusCode: http.StatusBadRequest},
			},
			validateOutput: func(duration time.Duration) bool {
				return duration > 5
			},
		},
		{
			name: "Do not retry a 400 error after 6 tries",
			args: args{
				n:    6,
				r:    &http.Request{},
				resp: &http.Response{StatusCode: http.StatusBadRequest},
			},
			validateOutput: func(duration time.Duration) bool {
				return duration == -1
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RetryBackoff(tt.args.n, tt.args.r, tt.args.resp); !tt.validateOutput(got) {
				t.Errorf("RetryBackoff() = %v which is not valid according to the validateOutput()", got)
			}
		})
	}
}
