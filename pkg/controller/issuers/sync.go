/*
Copyright 2021 The cert-manager Authors.

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

package issuers

import (
	"context"
	"reflect"

	"k8s.io/apimachinery/pkg/util/errors"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	internalissuers "github.com/jetstack/cert-manager/pkg/controller/internal/issuers"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	errorInitIssuer = "ErrInitIssuer"
)

func (c *Controller) Sync(ctx context.Context, issuer cmapi.GenericIssuer) (err error) {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	if !c.issuerBackend.Implements(issuer) {
		dbg.Info("issuer spec type does not match issuer backend so skipping processing")
		return nil
	}

	issuerCopy := issuer.Copy()
	defer func() {
		if _, saveErr := c.updateIssuerStatus(ctx, issuer, issuerCopy); saveErr != nil {
			err = errors.NewAggregate([]error{saveErr, err})
		}
	}()

	if err := c.issuerBackend.Setup(ctx, issuerCopy); err != nil {
		log.Error(err, errorInitIssuer)
		return err
	}

	return nil
}

func (c *Controller) updateIssuerStatus(ctx context.Context, old, new cmapi.GenericIssuer) (cmapi.GenericIssuer, error) {
	if reflect.DeepEqual(old.GetStatus(), new.GetStatus()) {
		return nil, nil
	}
	return internalissuers.UpdateStatus(ctx, c.cmClient, new)
}
