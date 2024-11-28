/*
Copyright 2023 The cert-manager Authors.

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

package ssaclient

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type applyPatch struct {
	patch []byte
}

var _ client.Patch = applyPatch{}

func (p applyPatch) Data(_ client.Object) ([]byte, error) {
	return p.patch, nil
}

func (p applyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

func (p applyPatch) String() string {
	return string(p.patch)
}
