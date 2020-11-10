/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package genericissuer

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

// assertErrorIs checks that the supplied error has the target error in its chain.
// TODO Upgrade to next release of testify package which has this built in.
func assertErrorIs(t *testing.T, err, target error) {
	if assert.Error(t, err) {
		assert.Truef(t, errors.Is(err, target), "unexpected error type. err: %v, target: %v", err, target)
	}
}

// assertIssuerHasCondition checks that the supplied issuer has a condition with the expected type and status.
func assertIssuerHasCondition(t *testing.T, issuer cmapi.GenericIssuer, condition cmapi.IssuerCondition) {
	assert.Truef(t, apiutil.IssuerHasCondition(
		issuer,
		condition,
	), "issuer does not have expected condition. expected: %#v, actual: %#v", condition, issuer.GetStatus().Conditions)
}
