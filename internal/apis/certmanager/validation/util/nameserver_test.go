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
	"testing"
)

func TestValidNameserver(t *testing.T) {
	tests := []struct {
		name       string
		nameserver string
		want       string
		wantErr    bool
	}{
		{
			name:       "IPv4 with no port should return port 53",
			nameserver: "8.8.8.8",
			want:       "8.8.8.8:53",
		},
		{
			name:       "IPv4 with : but no port number should return port 53",
			nameserver: "8.8.8.8:",
			want:       "8.8.8.8:53",
		},
		{
			name:       "IPv4 with port number should return the same",
			nameserver: "8.8.8.8:5353",
			want:       "8.8.8.8:5353",
		},
		{
			name:       "IPv6 with no port should return port 53",
			nameserver: "[2001:db8::1]",
			want:       "[2001:db8::1]:53",
		},
		{
			name:       "IPv6 with : but no port number should return port 53",
			nameserver: "[2001:db8::1]:",
			want:       "[2001:db8::1]:53",
		},
		{
			name:       "IPv6 with port number should return the same",
			nameserver: "[2001:db8::1]:5353",
			want:       "[2001:db8::1]:5353",
		},
		{
			name:       "DNS name with no port should return port 53",
			nameserver: "nameserver.com",
			want:       "nameserver.com:53",
		},
		{
			name:       "DNS name with : but no port number should return port 53",
			nameserver: "nameserver.com:",
			want:       "nameserver.com:53",
		},
		{
			name:       "DNS name with port number should return the same",
			nameserver: "nameserver.com:5353",
			want:       "nameserver.com:5353",
		},
		{
			name:       "Non unenclosed IPv6 should error",
			nameserver: "2001:db8::1:5353",
			wantErr:    true,
		},
		{
			name:       "Port only should error",
			nameserver: ":53",
			wantErr:    true,
		},
		{
			name:       "Empty nameserver should error",
			nameserver: "",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidNameserver(tt.nameserver)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidNameserver() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidNameserver() got = %v, want %v", got, tt.want)
			}
		})
	}
}
