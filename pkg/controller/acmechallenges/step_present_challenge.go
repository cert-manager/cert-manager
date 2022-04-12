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
	"fmt"

	cmapiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

type presentChallenge struct {
	solver   solver
	issuer   cmapi.GenericIssuer
	recorder record.EventRecorder
}

var _ syncStep = &presentChallenge{}

func (o *presentChallenge) Initialize(ctx context.Context, state *syncState) error {
	o.solver = state.solver
	o.issuer = state.issuer
	o.recorder = state.controller.recorder
	return nil
}

func (o *presentChallenge) Evaluate(ctx context.Context, ch *cmacme.Challenge) (syncAction, error) {
	if ch.Status.Presented {
		return nil, nil
	}
	return o, nil
}

func (o *presentChallenge) Run(ctx context.Context, ch *cmacme.Challenge) error {
	presented := true
	conditionStatus := cmmeta.ConditionTrue
	reason := reasonPresented
	message := fmt.Sprintf("Presented challenge using %s challenge mechanism", ch.Spec.Type)
	err := o.solver.Present(ctx, o.issuer, ch)
	if err != nil {
		presented = false
		conditionStatus = cmmeta.ConditionFalse
		reason = reasonPresentError
		message = fmt.Sprintf("Error presenting challenge: %v", err)
	}
	ch.Status.Presented = presented
	cmapiutil.SetChallengeCondition(ch, ch.Generation, cmacme.ChallengConditionPresented, conditionStatus, reason, message)
	o.recorder.Event(ch, corev1.EventTypeNormal, reason, message)
	return nil
}
