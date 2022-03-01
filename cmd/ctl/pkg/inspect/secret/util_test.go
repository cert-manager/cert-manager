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

const testCertForFingerprinting = `-----BEGIN CERTIFICATE-----
MIICljCCAhugAwIBAgIUNAQr779ga/BNXyCpK7ddFbjAK98wCgYIKoZIzj0EAwMw
aTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzAeFw0yMTAyMjYxMDM1MDBaFw0yMjAyMjYxMDM1MDBaMDMxCzAJ
BgNVBAYTAkdCMQ0wCwYDVQQKEwRjbmNmMRUwEwYDVQQLEwxjZXJ0LW1hbmFnZXIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATd5gWH2rkzWBGrr1jCR6JDB0dZOizZ
jCt2gnzNfzZmEg3rqxPvIakfT1lsjL2HrQyBRMQGGZhj7RkN7/VUM+VUo4HWMIHT
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
DAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUCUEeUFyT7U3e6zP4q4VYEr2x0KcwHwYD
VR0jBBgwFoAUFkKAaJ18Vg9xFx3K7d5b7HjoSSMwVAYDVR0RBE0wS4IRY2VydC1t
YW5hZ2VyLnRlc3SBFHRlc3RAY2VydC1tYW5hZ2VyLmlvhwQKAAABhhpzcGlmZmU6
Ly9jZXJ0LW1hbmFnZXIudGVzdDAKBggqhkjOPQQDAwNpADBmAjEA3Fv1aP+dBtBh
+DThW0QQO/Xl0CHQRKnJmJ8JjnleaMYFVdHf7dcf0ZeyOC26aUkdAjEA/fvxvhcz
Dtj+gY2rewoeJv5Pslli+SEObUslRaVtUMGxwUbmPU2fKuZHWBfe2FfA
-----END CERTIFICATE-----
`

func Test_fingerprintCert(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "Fingerprint a valid cert",
			cert: MustParseCertificate(t, testCertForFingerprinting),
			want: "FF:D0:A8:85:0B:A4:5A:E1:FC:55:40:E1:FC:07:09:F1:02:AE:B9:EB:28:C4:01:23:B9:4F:C8:FA:9B:EF:F4:C1",
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
