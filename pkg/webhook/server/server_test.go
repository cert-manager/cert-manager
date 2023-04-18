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
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/webhook/handlers"
	"k8s.io/klog/v2/klogr"
)

func TestConvert(t *testing.T) {
	type testCase struct {
		name string
		in   runtime.Object
		err  string
		log  string
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
			log: "request received by converting webhook",
		},
		{
			name: "v1 conversion review with nil Request",
			in:   &apiextensionsv1.ConversionReview{},
			err:  "review.request was nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bufWriter = bytes.NewBuffer(nil)
			klog.SetOutput(bufWriter)
			klog.LogToStderr(false)
			log := klogr.New()

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
			if klog.V(logf.DebugLevel).Enabled() {
				assert.Contains(t, bufWriter.String(), tc.log)
			}
		})
	}
}

type validation struct {
	responseUID     types.UID
	responseAllowed bool
}

func (v *validation) Validate(ctx context.Context, admissionSpec *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if v.responseUID == "" {
		return nil
	}

	return &admissionv1.AdmissionResponse{
		UID:     v.responseUID,
		Allowed: v.responseAllowed,
	}
}

func TestValidate(t *testing.T) {
	type testCase struct {
		name string
		s    *Server
		in   runtime.Object
		err  string
		log  string
	}
	var admissionReqName = "admission"
	var admissionReqNameSpace = "admissionNamespace"
	var responseAllowed = false
	var responseUID = types.UID("123e4567-e89b-12d3-a456-426614174000")

	tests := []testCase{
		{
			name: "unsupported validation review type",
			in:   &apiextensionsv1.CustomResourceDefinition{},
			s: &Server{
				ValidationWebhook: &validation{
					responseUID:     responseUID,
					responseAllowed: responseAllowed,
				},
			},
			err: "request is not of type apiextensions v1",
		},
		{
			name: "unsupported validation review version",
			in: &admissionv1beta1.AdmissionReview{
				Request: &admissionv1beta1.AdmissionRequest{},
			},
			s: &Server{
				ValidationWebhook: &validation{
					responseUID:     responseUID,
					responseAllowed: responseAllowed,
				},
			},
			err: "request is not of type apiextensions v1",
		},
		{
			name: "v1 validation review",
			in: &admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					Name:      admissionReqName,
					Namespace: admissionReqNameSpace,
				},
			},
			s: &Server{
				ValidationWebhook: &validation{
					responseUID:     responseUID,
					responseAllowed: responseAllowed,
				},
			},
			log: "request received by validating webhook",
		},
		{
			name: "v1 validation review with nil response",
			in: &admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					Name:      admissionReqName,
					Namespace: admissionReqNameSpace,
				},
			},
			s: &Server{
				ValidationWebhook: &validation{},
			},
			log: "request received by validating webhook",
		},
		{
			name: "v1 validation review with nil Request",
			in:   &admissionv1.AdmissionReview{},
			s: &Server{
				ValidationWebhook: &validation{
					responseUID:     responseUID,
					responseAllowed: responseAllowed,
				},
			},
			log: "request received by validating webhook",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bufWriter = bytes.NewBuffer(nil)
			klog.SetOutput(bufWriter)
			klog.LogToStderr(false)
			log := klogr.New()

			tc.s.log = log

			out, err := tc.s.validate(context.TODO(), tc.in)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, out)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, out)
			if klog.V(logf.DebugLevel).Enabled() {
				assert.Contains(t, bufWriter.String(), tc.log)
			}
		})
	}
}
