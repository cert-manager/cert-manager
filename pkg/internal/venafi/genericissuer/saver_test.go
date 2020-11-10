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
	"testing"

	"github.com/stretchr/testify/assert"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

func TestSaverSync(t *testing.T) {
	type testCase struct {
		syncer      syncer
		issuerSaver issuerSaver
		ctx         context.Context
		issuer      cmapi.GenericIssuer
		saved       bool
		err         error
	}

	tests := map[string]testCase{
		"sync success / save success": {
			syncer: &fakeSyncer{},
			saved:  true,
		},
		"sync error / save success": {
			syncer: &fakeSyncer{errSync: errors.New("simulated sync error")},
			saved:  true,
			err:    errSync,
		},
		"sync success / save error": {
			syncer: &fakeSyncer{},
			issuerSaver: func(ctx context.Context, issuer cmapi.GenericIssuer) error {
				return errors.New("simulated save error")
			},
			saved: false,
			err:   errSave,
		},
		"sync error / save error / errSave": {
			syncer: &fakeSyncer{errSync: errors.New("simulated sync error")},
			issuerSaver: func(ctx context.Context, issuer cmapi.GenericIssuer) error {
				return errors.New("simulated save error")
			},
			saved: false,
			err:   errSave,
		},
		"sync error / save error / errSync": {
			syncer: &fakeSyncer{errSync: errors.New("simulated sync error")},
			issuerSaver: func(ctx context.Context, issuer cmapi.GenericIssuer) error {
				return errors.New("simulated save error")
			},
			saved: false,
			err:   errSync,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			saved := false

			s := &saver{
				syncer: tc.syncer,
				issuerSaver: func(ctx context.Context, issuer cmapi.GenericIssuer) error {
					if tc.issuerSaver != nil {
						return tc.issuerSaver(ctx, issuer)
					}
					saved = true
					return nil
				},
			}

			err := s.Sync(tc.ctx, tc.issuer)

			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assertErrorIs(t, err, tc.err)
			}

			assert.Equalf(t, tc.saved, saved, "unexpected save result. expected save: %v, actual save: %v", tc.saved, saved)
		})
	}
}
