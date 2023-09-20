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
	"fmt"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestComputeUniqueDeterministicNameFromObject(t *testing.T) {
	type args struct {
		crt *cmapi.Certificate
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Name generation short domains",
			args: args{
				crt: &cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "unit.test.jetstack.io",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "unit.test.jetstack.io",
					},
				},
			},
			wantErr: false,
			want:    "unit.test.jetstack.io-a985b709",
		},
		{
			name: "Name generation too long domains",
			args: args{
				crt: &cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab.jetstack.io",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab.jetstack.io",
					},
				},
			},
			wantErr: false,
			want:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-80b03781",
		},
		{
			name: "Name generation for dot as 54nd char",
			args: args{
				crt: &cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jetstack.io",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jetstack.io",
					},
				},
			},
			wantErr: false,
			want:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-b4232761",
		},
		{
			name: "Name generation for dot as 56td char",
			args: args{
				crt: &cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jetstack.io",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jetstack.io",
					},
				},
			},
			wantErr: false,
			want:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-00065a75",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComputeUniqueDeterministicNameFromObject(tt.args.crt.Name, tt.args.crt.Spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ComputeUniqueDeterministicNameFromObject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ComputeUniqueDeterministicNameFromObject() = %v, want %v", got, tt.want)
			}
			if len(got) > MaxPodNameLength {
				t.Errorf("len(ComputeUniqueDeterministicNameFromObject()) <= %v, want %v", len(got), 63)
			}
			if len(validation.IsQualifiedName(got)) != 0 {
				t.Errorf("ComputeUniqueDeterministicNameFromObject() = %v is not DNS-1123 valid", got)
			}
		})
	}
}

func TestDNSSafeShortenToNCharacters(t *testing.T) {
	type testcase struct {
		in        string
		maxLength int
		expOut    string
	}

	tests := []testcase{
		{
			in:        "aaaaaaaaaaaaaaa",
			maxLength: 3,
			expOut:    "aaa",
		},
		{
			in:        ".....",
			maxLength: 3,
			expOut:    "",
		},
		{
			in:        "aa.....",
			maxLength: 3,
			expOut:    "aa",
		},
		{
			in:        "aaa.....",
			maxLength: 3,
			expOut:    "aaa",
		},
		{
			in:        "a*aa.....",
			maxLength: 3,
			expOut:    "a*a",
		},
		{
			in:        "a**aa.....",
			maxLength: 3,
			expOut:    "a",
		},
	}

	for i, test := range tests {
		test := test
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			out := DNSSafeShortenToNCharacters(test.in, test.maxLength)
			if out != test.expOut {
				t.Errorf("expected %q, got %q", test.expOut, out)
			}
		})
	}
}

func TestComputeUniqueDeterministicNameFromData(t *testing.T) {
	type testcase struct {
		in        string
		maxLength int
		extraData [][]byte
		expOut    string
		expErr    bool
	}

	tests := []testcase{
		{
			in:        "aaaaaaaaaaaaaaa",
			maxLength: 3,
			expOut:    "",
			expErr:    true,
		},
		{
			in:        "aaaaaaaaaaaaaaa",
			maxLength: 9,
			expOut:    "a3f4d65c",
		},
		{
			in:        "aaaaaaaaaaaaaaa",
			maxLength: 10,
			expOut:    "a-a3f4d65c",
		},
		{
			in:        "aaaaaaaaaaaaaaa.",
			maxLength: 10,
			expOut:    "a-766d72fa",
		},
		{
			in:        "aaaaaaaaaaaaaaa",
			maxLength: 10,
			expOut:    "a-fe5193d4",
			extraData: [][]byte{[]byte("data")},
		},
		{
			in:        ".aaaaaaaaaaaaaaa",
			maxLength: 10,
			expOut:    "149b2a00",
		},
		{
			in:        "a.aaaaaaaaaaaaaaa",
			maxLength: 11,
			expOut:    "a-4e348967",
		},
		{
			in:        "a.aaa",
			maxLength: 9,
			expOut:    "a.aaa",
		},
		{
			in:        "a.aaa",
			maxLength: 9,
			extraData: [][]byte{[]byte("data")},
			expOut:    "38cda5a3",
		},
	}

	for i, test := range tests {
		test := test
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			out, err := ComputeUniqueDeterministicNameFromData(test.in, test.maxLength, test.extraData...)
			if (err != nil) != test.expErr {
				t.Errorf("expected err %v, got %v", test.expErr, err)
			}
			if out != test.expOut {
				t.Errorf("expected %q, got %q", test.expOut, out)
			}
		})
	}
}
