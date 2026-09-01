/*
Copyright 2026 The cert-manager Authors.

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

package informers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/cache"
)

// The base (non-filtered) Secret informer has no separate metadata informer,
// so AddMetadataEventHandler must be a no-op: it must not register the handler
// on the wrapped informer, which AddEventHandler already covers.
func Test_singleInformer_AddMetadataEventHandler_noop(t *testing.T) {
	wrapped := &stubSharedIndexInformer{}
	s := &singleInformer{wrapped}

	reg, err := s.AddMetadataEventHandler(cache.ResourceEventHandlerFuncs{})
	assert.NoError(t, err)
	assert.Nil(t, reg)
	assert.Equal(t, 0, wrapped.addEventHandlerCalls, "AddMetadataEventHandler on the base informer must not register the handler anywhere")

	_, err = s.AddEventHandler(cache.ResourceEventHandlerFuncs{})
	assert.NoError(t, err)
	assert.Equal(t, 1, wrapped.addEventHandlerCalls)
}
