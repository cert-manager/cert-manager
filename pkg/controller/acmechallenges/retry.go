package acmechallenges

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/smithy-go"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	"github.com/cert-manager/cert-manager/pkg/util/solverpicker"
	v2 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
)

const (
	ErrCodeRoute53AccessDenied = "AccessDeniedException"
)

func newRetrySolver(solver solver, orderLister v1.OrderLister, issuerHelper issuer.Helper) solver {
	return &retrySolver{
		solver:       solver,
		orderLister:  orderLister,
		issuerHelper: issuerHelper,
	}
}

type retrySolver struct {
	solver       solver
	orderLister  v1.OrderLister
	issuerHelper issuer.Helper
}

func (r *retrySolver) Present(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
	err := r.solver.Present(ctx, issuer, ch)
	if r.shouldRetry(err) {
		newCh, retryErr := r.getChallengeWithFreshSolver(ctx, ch)
		if retryErr != nil {
			return err
		}
		retryErr = r.solver.Present(ctx, issuer, newCh)
		if retryErr != nil {
			return err
		}
		return nil
	}
	return err
}

func (r *retrySolver) Check(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
	err := r.solver.Check(ctx, issuer, ch)
	if r.shouldRetry(err) {
		newCh, retryErr := r.getChallengeWithFreshSolver(ctx, ch)
		if retryErr != nil {
			return err
		}
		retryErr = r.solver.Check(ctx, issuer, newCh)
		if retryErr != nil {
			return err
		}
		return nil
	}
	return err
}

func (r *retrySolver) CleanUp(ctx context.Context, ch *cmacme.Challenge) error {
	err := r.solver.CleanUp(ctx, ch)
	if r.shouldRetry(err) {
		newCh, retryErr := r.getChallengeWithFreshSolver(ctx, ch)
		if retryErr != nil {
			return err
		}
		retryErr = r.solver.CleanUp(ctx, newCh)
		if retryErr != nil {
			return err
		}
		return nil
	}
	return err
}

func (r *retrySolver) getChallengeWithFreshSolver(ctx context.Context, ch *cmacme.Challenge) (*cmacme.Challenge, error) {
	newSolver, err := r.getFreshSolver(ctx, ch)
	if err != nil {
		return nil, err
	}
	//TODO: attemps only if the there is r change in the credentials
	newCh := ch.DeepCopy()
	newCh.Spec.Solver = *newSolver
	return newCh, nil
}

func (r *retrySolver) getFreshSolver(ctx context.Context, ch *cmacme.Challenge) (*cmacme.ACMEChallengeSolver, error) {
	orderRef := v2.GetControllerOf(ch)
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
		return nil, fmt.Errorf("no compatible solvers found for challenge %s", chType)
	}
	newSolver, _ := solverpicker.Pick(ctx, ch.Spec.DNSName, challenges, solvers, o)
	if newSolver == nil {
		return nil, fmt.Errorf("no compatible solvers found for challenge %s", chType)
	}
	return newSolver, nil
}

func (r *retrySolver) shouldRetry(err error) bool {
	var ae smithy.APIError
	// route53
	if errors.As(err, &ae) {
		return ae.ErrorCode() == ErrCodeRoute53AccessDenied
	}

	return false
}

// filterIncompatibleSolvers filter out the solvers that have different type from the original one
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
			if origSolver.DNS01.Akamai != nil && s.DNS01.Akamai == nil {
				continue
			}

			if origSolver.DNS01.AcmeDNS != nil && s.DNS01.AcmeDNS == nil {
				continue
			}

			if origSolver.DNS01.AzureDNS != nil && s.DNS01.AzureDNS == nil {
				continue
			}

			if origSolver.DNS01.CloudDNS != nil && s.DNS01.CloudDNS == nil {
				continue
			}

			if origSolver.DNS01.Cloudflare != nil && s.DNS01.Cloudflare == nil {
				continue
			}

			if origSolver.DNS01.DigitalOcean != nil && s.DNS01.DigitalOcean == nil {
				continue
			}

			if origSolver.DNS01.Route53 != nil && s.DNS01.Route53 == nil {
				continue
			}

			if origSolver.DNS01.RFC2136 != nil && s.DNS01.RFC2136 == nil {
				continue
			}

			if origSolver.DNS01.Webhook != nil && s.DNS01.Webhook == nil {
				continue
			}
		}

		result = append(result, s)
	}

	return result
}
