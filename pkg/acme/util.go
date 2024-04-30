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

package acme

import (
	corev1 "k8s.io/api/core/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// IsFinalState will return true if the given ACME State is a 'final' state.
// This is either one of 'ready', 'invalid' or 'expired'.
// The 'valid' state is a special case, as it is a final state for Challenges but
// not for Orders.
func IsFinalState(s cmacme.State) bool {
	if s == cmacme.Valid {
		return true
	}
	return IsFailureState(s)
}

func IsFailureState(s cmacme.State) bool {
	switch s {
	case cmacme.Invalid, cmacme.Expired, cmacme.Errored:
		return true
	}
	return false
}

// PrivateKeySelector will default the SecretKeySelector with a default secret key
// if one is not already specified.
func PrivateKeySelector(sel cmmeta.SecretKeySelector) cmmeta.SecretKeySelector {
	if len(sel.Key) == 0 {
		sel.Key = corev1.TLSPrivateKeyKey
	}
	return sel
}
