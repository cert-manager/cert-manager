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
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/aws/smithy-go"
	"github.com/digitalocean/godo"
	v2 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v3 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
	controller2 "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/solverpicker"
)

func newRetrySolver(solver solver, orderLister v1.OrderLister, issuerHelper issuer.Helper, issuerOptions controller2.IssuerOptions) solver {
	return &retrySolver{
		solver:        solver,
		orderLister:   orderLister,
		issuerHelper:  issuerHelper,
		issuerOptions: issuerOptions,
	}
}

type retrySolver struct {
	solver        solver
	orderLister   v1.OrderLister
	issuerHelper  issuer.Helper
	issuerOptions controller2.IssuerOptions
}

func (r *retrySolver) Present(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
	return r.withRetry(ctx, ch, issuer, func(newCtx context.Context, newIssuer cmapi.GenericIssuer, newCh *cmacme.Challenge) error {
		return r.solver.Present(newCtx, newIssuer, newCh)
	})
}

func (r *retrySolver) Check(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
	return r.withRetry(ctx, ch, issuer, func(newCtx context.Context, newIssuer cmapi.GenericIssuer, newCh *cmacme.Challenge) error {
		return r.solver.Check(newCtx, newIssuer, newCh)
	})
}

func (r *retrySolver) CleanUp(ctx context.Context, ch *cmacme.Challenge) error {
	return r.withRetry(ctx, ch, nil, func(newCtx context.Context, _ cmapi.GenericIssuer, newCh *cmacme.Challenge) error {
		return r.solver.CleanUp(newCtx, newCh)
	})
}

func (r *retrySolver) withRetry(
	ctx context.Context,
	ch *cmacme.Challenge,
	issuer cmapi.GenericIssuer,
	f func(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error) error {
	err := f(ctx, issuer, ch)
	if err == nil || !r.needsRetry(err) {
		return err
	}

	log := logf.WithResource(logf.FromContext(ctx, "Retry"), ch).WithValues("domain", ch.Spec.DNSName)
	newCh, retryErr := r.getChallengeWithFreshSolver(ctx, ch)
	if retryErr != nil {
		log.V(logf.InfoLevel).Info("failed to get fresh solver", "challenge", ch.Name, "err", retryErr)
		return err
	}
	retryErr = f(ctx, issuer, newCh)
	if retryErr != nil {
		log.V(logf.InfoLevel).Info("withRetry request failed", "challenge", ch.Name, "err", retryErr)
		return err

	}
	return nil
}

func (r *retrySolver) needsRetry(err error) bool {
	if err == nil {
		return false
	}

	var awsError smithy.APIError
	var digitalOceanError *godo.ErrorResponse
	// route53
	if errors.As(err, &awsError) {
		return awsError.ErrorCode() == strconv.Itoa(http.StatusForbidden)
	}
	// digitalocean
	if errors.As(err, &digitalOceanError) {
		return digitalOceanError.Response.StatusCode == http.StatusForbidden
	}

	return false
}

func (r *retrySolver) getChallengeWithFreshSolver(ctx context.Context, ch *cmacme.Challenge) (*cmacme.Challenge, error) {
	newSolver, err := r.getFreshSolver(ctx, ch)
	if err != nil {
		return nil, err
	}
	if !r.shouldRetry(ch.Spec.IssuerRef, ch.Spec.Solver, *newSolver) {
		return nil, fmt.Errorf("solver has not changed")
	}
	newCh := ch.DeepCopy()
	newCh.Spec.Solver = *newSolver
	return newCh, nil
}

func (r *retrySolver) getFreshSolver(ctx context.Context, ch *cmacme.Challenge) (*cmacme.ACMEChallengeSolver, error) {
	orderRef := v2.GetControllerOf(ch)
	if orderRef == nil {
		return nil, fmt.Errorf("challenge %s does not have a owner", ch.Name)
	}
	o, err := r.orderLister.Orders(ch.ObjectMeta.Namespace).Get(orderRef.Name)
	if err != nil {
		return nil, fmt.Errorf("unable to get order %s: %w", orderRef.Name, err)
	}
	genericIssuer, err := r.issuerHelper.GetGenericIssuer(ch.Spec.IssuerRef, ch.ObjectMeta.Namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to get issuer %s: %w", ch.Spec.IssuerRef.Name, err)
	}

	chType := strings.ToLower(string(ch.Spec.Type))
	challenges := []cmacme.ACMEChallenge{
		{Type: chType},
	}
	issuerSolvers := genericIssuer.GetSpec().IssuerConfig.ACME.Solvers
	solvers := r.filterIncompatibleSolvers(ch.Spec.Solver, issuerSolvers)
	if len(solvers) == 0 {
		return nil, fmt.Errorf("no compatible solvers found for challenge %s", ch.Spec.DNSName)
	}
	newSolver, _ := solverpicker.Pick(ctx, ch.Spec.DNSName, challenges, solvers, o)
	if newSolver == nil {
		return nil, fmt.Errorf("no compatible solvers found for challenge %s", ch.Spec.DNSName)
	}
	return newSolver, nil
}

// filterIncompatibleSolvers filter out the solvers that have different type from the original one.
func (r *retrySolver) filterIncompatibleSolvers(origSolver cmacme.ACMEChallengeSolver, newSolvers []cmacme.ACMEChallengeSolver) []cmacme.ACMEChallengeSolver {
	result := make([]cmacme.ACMEChallengeSolver, 0, cap(newSolvers))

	for _, s := range newSolvers {
		if origSolver.DNS01 != nil && s.DNS01 == nil {
			continue
		}
		if origSolver.HTTP01 != nil && s.HTTP01 == nil {
			continue
		}

		if origSolver.DNS01 != nil && s.DNS01 != nil {
			if origSolver.DNS01.DigitalOcean != nil && s.DNS01.DigitalOcean == nil {
				continue
			}

			if origSolver.DNS01.Route53 != nil && s.DNS01.Route53 == nil {
				continue
			}
		}

		result = append(result, s)
	}

	return result
}

func (r *retrySolver) shouldRetry(issueRef v3.IssuerReference, origSolver, newSolver cmacme.ACMEChallengeSolver) bool {
	if origSolver.DNS01.DigitalOcean != nil && newSolver.DNS01.DigitalOcean != nil {
		return !reflect.DeepEqual(origSolver.DNS01.DigitalOcean.Token, newSolver.DNS01.DigitalOcean.Token)
	}

	if origSolver.DNS01.Route53 != nil && newSolver.DNS01.Route53 != nil {
		return !reflect.DeepEqual(origSolver.DNS01.Route53, newSolver.DNS01.Route53) || r.issuerOptions.CanUseAmbientCredentialsFromRef(issueRef)
	}

	return false
}
