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
	cmutil "github.com/cert-manager/cert-manager/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestComputeName(t *testing.T) {
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
			want:    "unit.test.jetstack.io-1683025094",
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
			want:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-108802726",
		},
		{
			name: "Name generation for dot as 52nd char",
			args: args{
				crt: &cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jetstack.io",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jetstack.io",
					},
				},
			},
			wantErr: false,
			want:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-225297437",
		},
		{
			name: "Name generation for dot as 54td char",
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
			want:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1448584771",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComputeName(tt.args.crt.Name, tt.args.crt.Spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ComputeName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ComputeName() = %v, want %v", got, tt.want)
			}
			if len(validation.IsQualifiedName(got)) != 0 {
				t.Errorf("ComputeName() = %v is not DNS-1123 valid", got)
			}
		})
	}
}

func TestComputeUniqueDeterministicNameFromData(t *testing.T) {
	type testcase struct {
		in     string
		expOut string
	}

	randomString61 := cmutil.RandStringRunes(61)

	tests := []testcase{
		{
			in:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expOut: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-014e7a7f",
		},
		{
			in:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expOut: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			in:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
			expOut: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
		},
		{
			in:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaa",
			expOut: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaa",
		},
		{
			in:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaa",
			expOut: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-72314ca8",
		},
		{
			in:     randomString61,
			expOut: randomString61,
		},
	}

	for i, test := range tests {
		test := test
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			out, err := ComputeUniqueDeterministicNameFromData(test.in)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if out != test.expOut {
				t.Errorf("expected %q, got %q", test.expOut, out)
			}
		})
	}

	// Test that the output is unique for different inputs
	inputs := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaa",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaa",
		randomString61,
		randomString61 + "a",
		randomString61 + "b",
		randomString61 + "c",
	}

	outputs := make(map[string]struct{})
	for _, in := range inputs {
		out, err := ComputeUniqueDeterministicNameFromData(in)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if _, ok := outputs[out]; ok {
			t.Errorf("output %q already seen", out)
		}
		outputs[out] = struct{}{}
	}
}
