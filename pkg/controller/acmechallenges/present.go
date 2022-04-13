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

package acmechallenges

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

const (
	reasonPresentError = "PresentError"
	reasonPresented    = "Presented"
)

// presentStep "presents" (aka deploys) the resources needed for a Challenge.
// E.g. DNS records or Ingress configuration.
type presentStep struct {
	ch       *cmacme.Challenge
	solver   solver
	issuer   cmapi.GenericIssuer
	recorder record.EventRecorder
}

// Required checks the Challenge status to see whether this step has already been run.
func (o *presentStep) Required() bool {
	return !o.ch.Status.Presented
}

// Run invokes solver.Present and updates the Challenge.Status with the success
// or failure of that operation.
func (o *presentStep) Run(ctx context.Context) error {
	if err := o.solver.Present(ctx, o.issuer, o.ch); err != nil {
		o.recorder.Eventf(o.ch, corev1.EventTypeWarning, reasonPresentError, "Error presenting challenge: %v", err)
		o.ch.Status.Reason = err.Error()
		return err
	}
	o.ch.Status.Reason = ""
	o.ch.Status.Presented = true
	o.recorder.Eventf(o.ch, corev1.EventTypeNormal, reasonPresented, "Presented challenge using %s challenge mechanism", o.ch.Spec.Type)
	return nil
}
