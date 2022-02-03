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

package predicate

import (
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestCertificateRequestRevision(t *testing.T) {
	requestWithRevision := func(s int) *cmapi.CertificateRequest {
		return &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					cmapi.CertificateRequestRevisionAnnotationKey: fmt.Sprintf("%d", s),
				},
			},
		}
	}
	tests := map[string]struct {
		revision int
		request  *cmapi.CertificateRequest
		expected bool
	}{
		"returns true if revision matches": {
			revision: 30,
			request:  requestWithRevision(30),
			expected: true,
		},
		"returns false if revision does not match": {
			revision: 29,
			request:  requestWithRevision(30),
			expected: false,
		},
		"returns false if revision is not set": {
			revision: 0,
			request:  &cmapi.CertificateRequest{},
			expected: false,
		},
		"returns false if revision is empty": {
			revision: 0,
			request: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "",
					},
				},
			},
			expected: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := CertificateRequestRevision(test.revision)(test.request)
			if got != test.expected {
				t.Errorf("unexpected response: got=%t, exp=%t", got, test.expected)
			}
		})
	}
}
