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

// This package is a legacy and exists to satisfy the issuer and clusterissuer controllers.
// They expect a plugin for every builtin issuer type
// and log an error if there isn't registered issuer handler.
// Venafi Issuer and ClusterIssuer are now handled by separate controllers
// in pkg/controllers/{cluster}issuer/venafi.
package venafi

import (
	"context"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// venafi is registered to prevent the issuer controller logging an error when it encounters a Venafi Issuer or ClusterIssuer
type venafi struct{}

// NewVenafi returns a no-op issuer interface
func NewVenafi(_ *controller.Context, _ cmapi.GenericIssuer) (issuer.Interface, error) {
	return &venafi{}, nil
}

// Setup does nothing
func (o *venafi) Setup(_ context.Context) error {
	return nil
}

func init() {
	issuer.RegisterIssuer(apiutil.IssuerVenafi, NewVenafi)
}
