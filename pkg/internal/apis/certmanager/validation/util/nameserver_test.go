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
			name:       "IPv4 with no port should should return port 53",
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
			name:       "IPv6 with no port should should return port 53",
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
			name:       "DNS name with no port should should return port 53",
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
