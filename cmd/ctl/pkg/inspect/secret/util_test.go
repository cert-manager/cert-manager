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

package secret

import (
	"crypto/x509"
	"reflect"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func Test_fingerprintCert(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Fingerprint a valid cert",
			cert: MustParseCertificate(t, testCert),
			want: "A9:4D:28:6F:1E:78:4A:72:C7:38:01:7C:31:CC:42:09:C7:46:9C:6A:26:C5:71:1A:F1:35:11:6E:BA:C3:BA:5A",
		},
		{
			name: "Fingerprint nil",
			cert: nil,
			want: "",
		},
		{
			name: "Fingerprint invalid cert",
			cert: &x509.Certificate{Raw: []byte("fake")},
			want: "B5:D5:4C:39:E6:66:71:C9:73:1B:9F:47:1E:58:5D:82:62:CD:4F:54:96:3F:0C:93:08:2D:8D:CF:33:4D:4C:78",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fingerprintCert(tt.cert); got != tt.want {
				t.Errorf("fingerprintCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_printKeyUsage(t *testing.T) {
	type args struct {
		in []cmapi.KeyUsage
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printKeyUsage(tt.args.in); got != tt.want {
				t.Errorf("printKeyUsage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_printOrNone(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "Print none on empty",
			in:   "",
			want: "<none>",
		},
		{
			name: "Print value on not empty",
			in:   "ok",
			want: "ok",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printOrNone(tt.in); got != tt.want {
				t.Errorf("printOrNone() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_printSlice(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{
			name: "Print test slice multiple objects",
			in:   []string{"test", "ok"},
			want: `
		- test
		- ok`,
		},
		{
			name: "Print test slice one object",
			in:   []string{"test"},
			want: "\n\t\t- test",
		},
		{
			name: "Print nil slice",
			in:   nil,
			want: "<none>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printSlice(tt.in); got != tt.want {
				t.Errorf("printSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_printSliceOrOne(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{
			name: "Print test slice multiple objects",
			in:   []string{"test", "ok"},
			want: `
		- test
		- ok`,
		},
		{
			name: "Print test slice one object",
			in:   []string{"test"},
			want: "test",
		},
		{
			name: "Print nil slice",
			in:   nil,
			want: "<none>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printSliceOrOne(tt.in); got != tt.want {
				t.Errorf("printSliceOrOne() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_splitPEMs(t *testing.T) {
	type args struct {
		certData []byte
	}
	tests := []struct {
		name     string
		certData []byte
		want     [][]byte
		wantErr  bool
	}{
		{
			name:     "Single PEM in file",
			certData: []byte(testCert),
			want:     [][]byte{[]byte(testCert)},
			wantErr:  false,
		},
		{
			name:     "2 PEMs in file",
			certData: []byte(testCert + "\n" + testCert),
			want:     [][]byte{[]byte(testCert), []byte(testCert)},
			wantErr:  false,
		},
		{
			name:     "Invalid input after a valid PEM",
			certData: []byte(testCert + "\n\ninvalid"),
			want:     [][]byte{[]byte(testCert)},
			wantErr:  false,
		},
		{
			name:     "Invalid input without PEM block",
			certData: []byte("invalid"),
			want:     nil,
			wantErr:  false,
		},
		// TODO: somehow find an error case the PEM encoder/decoder is quite error resistant
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitPEMs(tt.certData)
			if (err != nil) != tt.wantErr {
				t.Errorf("splitPEMs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitPEMs() got = %v, want %v", got, tt.want)
			}
		})
	}
}
