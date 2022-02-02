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

package server

import (
	"context"
	"testing"

	logtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cert-manager/cert-manager/pkg/webhook/handlers"
)

func TestConvert(t *testing.T) {
	type testCase struct {
		name string
		in   runtime.Object
		err  string
	}
	tests := []testCase{
		{
			name: "unsupported conversion review type",
			in:   &apiextensionsv1.CustomResourceDefinition{},
			err:  "unsupported conversion review type: *v1.CustomResourceDefinition",
		},
		{
			name: "unsupported conversion review version",
			in: &apiextensionsv1beta1.ConversionReview{
				Request: &apiextensionsv1beta1.ConversionRequest{},
			},
			err: "unsupported conversion review type: *v1beta1.ConversionReview",
		},
		{
			name: "v1 conversion review",
			in: &apiextensionsv1.ConversionReview{
				Request: &apiextensionsv1.ConversionRequest{},
			},
		},
		{
			name: "v1 conversion review with nil Request",
			in:   &apiextensionsv1.ConversionReview{},
			err:  "review.request was nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log := logtesting.NewTestLogger(t)
			s := &Server{
				ConversionWebhook: handlers.NewSchemeBackedConverter(log, defaultScheme),
				log:               log,
			}
			out, err := s.convert(context.TODO(), tc.in)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, out)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, out)
		})
	}
}
