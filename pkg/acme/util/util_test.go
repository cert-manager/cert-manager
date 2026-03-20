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

func TestRetryBackoff_RateLimit(t *testing.T) {
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
			name: "Retry a 429 error on first attempt with exponential backoff",
			args: args{
				n: 0,
				r: &http.Request{},
				resp: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{},
				},
			},
			validateOutput: func(duration time.Duration) bool {
				// First attempt: 2^0 * 2s = 2s + jitter, should be between 2s and 4s
				return duration >= 2*time.Second && duration <= 4*time.Second
			},
		},
		{
			name: "Retry a 429 error with Retry-After header in seconds",
			args: args{
				n: 0,
				r: &http.Request{},
				resp: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{"5"}},
				},
			},
			validateOutput: func(duration time.Duration) bool {
				// Should respect the 5 second Retry-After + jitter
				return duration >= 5*time.Second && duration <= 7*time.Second
			},
		},
		{
			name: "Retry a 429 error with Retry-After header capped at max delay",
			args: args{
				n: 0,
				r: &http.Request{},
				resp: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{"120"}},
				},
			},
			validateOutput: func(duration time.Duration) bool {
				// Should be capped at rateLimitMaxDelay (60s)
				return duration == rateLimitMaxDelay
			},
		},
		{
			name: "Retry a 429 error with increasing backoff on attempt 3",
			args: args{
				n: 3,
				r: &http.Request{},
				resp: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{},
				},
			},
			validateOutput: func(duration time.Duration) bool {
				// Third attempt: 2^3 * 2s = 16s + jitter
				return duration >= 16*time.Second && duration <= 18*time.Second
			},
		},
		{
			name: "Do not retry a 429 error after too many attempts",
			args: args{
				n: 11,
				r: &http.Request{},
				resp: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{},
				},
			},
			validateOutput: func(duration time.Duration) bool {
				return duration == -1
			},
		},
		{
			name: "Retry a 429 error with empty Retry-After header uses exponential backoff",
			args: args{
				n: 1,
				r: &http.Request{},
				resp: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{""}},
				},
			},
			validateOutput: func(duration time.Duration) bool {
				// Should fall back to exponential backoff: 2^1 * 2s = 4s + jitter
				return duration >= 4*time.Second && duration <= 6*time.Second
			},
		},
		{
			name: "Retry a 429 error with invalid Retry-After header uses exponential backoff",
			args: args{
				n: 0,
				r: &http.Request{},
				resp: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{"not-a-number"}},
				},
			},
			validateOutput: func(duration time.Duration) bool {
				// Should fall back to exponential backoff: 2^0 * 2s = 2s + jitter
				return duration >= 2*time.Second && duration <= 4*time.Second
			},
		},
		{
			name: "Do not retry other 4xx errors",
			args: args{
				n: 0,
				r: &http.Request{},
				resp: &http.Response{
					StatusCode: http.StatusForbidden,
					Header:     http.Header{},
				},
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
