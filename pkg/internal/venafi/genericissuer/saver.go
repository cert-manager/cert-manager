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
	"context"
	"errors"
	"fmt"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

// issuerSaver allows us to simulate save errors unit tests
type issuerSaver func(ctx context.Context, issuer cmapi.GenericIssuer) error

// saver wraps another syncer and attempts to update the Status of the supplied GenericIssuer.
type saver struct {
	syncer
	issuerSaver issuerSaver
}

var _ syncer = &saver{}

var (
	errSave = errors.New("error saving issuer")
)

// Sync always attempts to update the status of
// the supplied GenericIssuer and returns both the error of the wrapped Sync and
// any error encountered while saving the resource.
// This ensures that any conditions that have been set by the wrapped Sync are
// saved to the API server.
// Separating the API server interactions from the resource mutations makes
// it easier to test error handling.
func (o *saver) Sync(ctx context.Context, issuer cmapi.GenericIssuer) error {
	syncErr := o.syncer.Sync(ctx, issuer)
	if syncErr != nil {
		syncErr = fmt.Errorf("%w: %v", errSync, syncErr)
	}

	saveErr := o.issuerSaver(ctx, issuer)
	if saveErr != nil {
		saveErr = fmt.Errorf("%w: %v", errSave, saveErr)
	}

	return utilerrors.NewAggregate([]error{syncErr, saveErr})
}
