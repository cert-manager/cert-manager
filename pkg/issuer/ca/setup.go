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

package ca

import (
	"context"
	"fmt"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/kube"
)

// Setup verifies signing CA.
func (c *CA) Setup(ctx context.Context, issuer v1.GenericIssuer) error {
	log := logf.FromContext(ctx, "setup")

	cert, err := kube.SecretTLSCert(ctx, c.secretsLister, c.resourceNamespace, issuer.GetSpec().CA.SecretName)
	if err != nil {
		return fmt.Errorf("error getting keypair for CA issuer: %w", err)
	}

	_, err = kube.SecretTLSKey(ctx, c.secretsLister, c.resourceNamespace, issuer.GetSpec().CA.SecretName)
	if err != nil {
		return fmt.Errorf("error getting keypair for CA issuer: %w", err)
	}

	log = logf.WithRelatedResourceName(log, issuer.GetSpec().CA.SecretName, c.resourceNamespace, "Secret")
	if !cert.IsCA {
		return fmt.Errorf("error getting keypair for CA issuer: certificate is not a CA")
	}

	log.V(logf.DebugLevel).Info("signing CA verified")

	return nil
}
