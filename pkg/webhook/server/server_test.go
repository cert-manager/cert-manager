package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"

	testingcmlogs "github.com/jetstack/cert-manager/pkg/logs/testing"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers"
)

func TestConvert(t *testing.T) {
	type testCase struct {
		name string
		in   runtime.Object
		out  runtime.Object
		err  string
	}
	tests := []testCase{
		{
			name: "unsupported conversion review type",
			in:   &apiextensionsv1.CustomResourceDefinition{},
			err:  "unsupported conversion review type: *v1.CustomResourceDefinition",
		},
		{
			name: "v1beta1 conversion review",
			in: &apiextensionsv1beta1.ConversionReview{
				Request: &apiextensionsv1beta1.ConversionRequest{},
			},
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
		{
			name: "v1beta1 conversion review with nil Request",
			in:   &apiextensionsv1beta1.ConversionReview{},
			err:  "review.request was nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log := &testingcmlogs.TestLogger{T: t}
			s := &Server{
				ConversionWebhook: handlers.NewSchemeBackedConverter(log, defaultScheme),
				Log:               log,
			}
			out, err := s.convert(tc.in)
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
