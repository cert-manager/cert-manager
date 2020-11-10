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

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	venaficlient "github.com/jetstack/cert-manager/pkg/internal/venafi/client"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type syncer interface {
	Sync(context.Context, cmapi.GenericIssuer) error
}

type realSyncer struct {
	venafiClientBuilder venaficlient.Builder
}

var _ syncer = &realSyncer{}

var (
	errClientBuilder         = errors.New("venaficlientbuilder error")
	errAuthenticate          = errors.New("authenticate error")
	errRotateCredentials     = errors.New("rotatecredentials error")
	errReadZoneConfiguration = errors.New("readzoneconfiguration error")
)

// Sync checks the Venafi configuration of the supplied GenericIssuer allows a
// connection to be established to a Venafi API server.
// The Ready condition of the supplied GenericIssuer is set to true if all
// checks succeed and is set to false if any of the steps fails.
func (o *realSyncer) Sync(ctx context.Context, issuer cmapi.GenericIssuer) (err error) {
	log := logf.FromContext(ctx, "syncer", "Sync")
	ctx = logf.NewContext(ctx, log)

	defer func() {
		if err != nil {
			apiutil.SetIssuerCondition(
				issuer,
				cmapi.IssuerConditionReady,
				cmmeta.ConditionFalse,
				"Sync",
				err.Error(),
			)
		}
	}()

	vc, err := o.venafiClientBuilder(ctx, issuer)
	if err != nil {
		return fmt.Errorf("%w: %v", errClientBuilder, err)
	}

	if err := vc.Authenticate(); err != nil {
		if !errors.Is(err, venaficlient.ErrAccessTokenExpired) && !errors.Is(err, venaficlient.ErrAccessTokenMissing) {
			return fmt.Errorf("%w: %v", errAuthenticate, err)
		}
		if err := vc.RotateCredentials(); err != nil {
			return fmt.Errorf("%w: %v", errRotateCredentials, err)
		}
	}

	if _, err := vc.ReadZoneConfiguration(); err != nil {
		return fmt.Errorf("%w: %v", errReadZoneConfiguration, err)
	}

	apiutil.SetIssuerCondition(
		issuer,
		cmapi.IssuerConditionReady,
		cmmeta.ConditionTrue,
		"Sync",
		"Successfully connected to the Venafi server and checked zone configuration",
	)

	return nil
}
