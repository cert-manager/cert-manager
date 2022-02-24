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

package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NewContextFactory(t *testing.T) {
	ctxFactory, err := NewContextFactory(context.TODO(), ContextOptions{
		APIServerHost:      "localhost:8443",
		KubernetesAPIQPS:   10,
		KubernetesAPIBurst: 10,
	})
	assert.NoError(t, err)

	// Ensure a single RateLimiter is preserved across Contexts.
	ctx1, err := ctxFactory.Build("test-1")
	assert.NoError(t, err)
	ctx2, err := ctxFactory.Build("test-2")
	assert.NoError(t, err)

	assert.NotNil(t, ctx1.RESTConfig.RateLimiter)
	assert.Same(t, ctx1.RESTConfig.RateLimiter, ctx2.RESTConfig.RateLimiter)
}
