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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/validation"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
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

func TestDNSSafeShortenToNCharacters(t *testing.T) {
	type testcase struct {
		in        string
		maxLength int
		expOut    string
	}

	tests := []testcase{
		{
			in:        "aaaaaaaaaaaaaaa",
			maxLength: 0,
			expOut:    "",
		},
		{
			in:        "aa-----aaaa",
			maxLength: 5,
			expOut:    "aa",
		},
		{
			in:        "aa11111aaaa",
			maxLength: 5,
			expOut:    "aa111",
		},
		{
			in:        "aaAAAAAaaaa",
			maxLength: 5,
			expOut:    "aaAAA",
		},
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
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			out := DNSSafeShortenToNCharacters(test.in, test.maxLength)
			if out != test.expOut {
				t.Errorf("expected %q, got %q", test.expOut, out)
			}
		})
	}
}

func TestComputeSecureUniqueDeterministicNameFromData(t *testing.T) {
	type testcase struct {
		in        string
		maxLength int
		expOut    string
		expErr    bool
	}

	aString64 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	randomString64 := rand.String(64)

	tests := []testcase{
		{
			in:        "aaaa",
			maxLength: 3, // must be at least 64
			expOut:    "",
			expErr:    true,
		},
		{
			in:        aString64,
			maxLength: 64,
			expOut:    aString64,
		},
		{
			in:        aString64[:10],
			maxLength: 64,
			expOut:    aString64[:10],
		},
		{
			in:        "b" + aString64,
			maxLength: 64,
			expOut:    "08ba353c3a64d6186cac33ae87b2bd29700803754b34f77dc4d3a45e66316745",
		},
		{
			in:        "b" + aString64,
			maxLength: 65,
			expOut:    "b" + aString64,
		},
		{
			in:        "bb" + aString64,
			maxLength: 65,
			expOut:    "824cc1084d15d9bff4dda12c92066ff5d15ef2f9847c47347836cee174138ca0",
		},
		{
			in:        "bbb" + aString64,
			maxLength: 66,
			expOut:    "b-9a956f515497faf6c2e733e5c2a0e35700ff0b9457e6fd163f30bfe5ec81d13c",
		},
		{
			in:        ".bb" + aString64,
			maxLength: 66,
			expOut:    "efd1f8e9b2f02af94b0d00c03eaddbde3a510b626eb92022f1f25bcc74eedb5b",
		},
		{
			in:        "b.b" + aString64,
			maxLength: 66,
			expOut:    "b-f0673c1af88891be1ecfe74876e460de28e073a0bb78d3308fb41617db4c2ca5",
		},
		{
			in:        "bbbbbbbbbbbbbc............." + aString64,
			maxLength: 79,
			expOut:    "bbbbbbbbbbbbbc-d1b69a0803d97526b868335f95a8bc6fcf02e8e08644264c470faded0ca42033",
		},
		{
			in:        "bbbbbbbbbbbbbc............." + aString64,
			maxLength: 80,
			expOut:    "bbbbbbbbbbbbbc-d1b69a0803d97526b868335f95a8bc6fcf02e8e08644264c470faded0ca42033",
		},
		{
			in:        "bbbbbbbbbbbbbc............." + aString64,
			maxLength: 90,
			expOut:    "bbbbbbbbbbbbbc-d1b69a0803d97526b868335f95a8bc6fcf02e8e08644264c470faded0ca42033",
		},
		{
			in:        randomString64,
			maxLength: 64,
			expOut:    randomString64,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			out, err := ComputeSecureUniqueDeterministicNameFromData(test.in, test.maxLength)
			if (err != nil) != test.expErr {
				t.Errorf("expected err %v, got %v", test.expErr, err)
			}
			if len(out) > test.maxLength {
				t.Errorf("expected output to be at most %d characters, got %d", test.maxLength, len(out))
			}
			if out != test.expOut {
				t.Errorf("expected %q, got %q", test.expOut, out)
			}
		})
	}

	aString70 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	randomString70 := rand.String(70)

	// Test that the output is unique for different inputs
	inputs := []string{
		aString70,
		aString70 + "a",
		aString70 + "b",
		aString70 + ".",
		"." + aString70,
		"...................." + aString70,
		"...................a" + aString70,
		"a..................." + aString70,
		randomString70,
		randomString70 + "a",
		randomString70 + "b",
		randomString70 + "c",
	}

	outputs := make(map[string]struct{})
	for _, in := range inputs {
		out, err := ComputeSecureUniqueDeterministicNameFromData(in, 80)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if _, ok := outputs[out]; ok {
			t.Errorf("output %q already seen", out)
		}
		outputs[out] = struct{}{}
	}
}
