/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package http

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

func (s *Solver) ensureNetworkPolicy(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (*networkingv1.NetworkPolicy, error) {
	log := logf.FromContext(ctx).WithName("ensureNetworkPolicy")

	log.V(logf.DebugLevel).Info("checking for existing HTTP01 solver network policies for challenge")
	existingNetworkPolicies, err := s.getNetworkPoliciesForChallenge(ctx, ch)
	if err != nil {
		return nil, err
	}
	if len(existingNetworkPolicies) == 1 {
		logf.WithRelatedResource(log, existingNetworkPolicies[0]).Info("found one existing HTTP01 solver Network Policy for challenge resource")
		return existingNetworkPolicies[0], nil
	}
	if len(existingNetworkPolicies) > 1 {
		log.Info("multiple challenge solver network policies found for challenge. cleaning up all existing services.")
		err := s.cleanupNetworkPolicy(ctx, ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("multiple existing challenge solver network policies found and cleaned up. retrying challenge sync")
	}

	log.Info("creating HTTP01 challenge solver network policy")
	return s.createNetworkPolicy(issuer, ch)
}

// getNetworkPoliciesForChallenge returns a list of network policies that were created to solve
// http challenges for the given domain
func (s *Solver) getNetworkPoliciesForChallenge(ctx context.Context, ch *v1alpha1.Challenge) ([]*networkingv1.NetworkPolicy, error) {
	log := logf.FromContext(ctx)

	podLabels := podLabels(ch)
	selector := labels.NewSelector()
	for key, val := range podLabels {
		req, err := labels.NewRequirement(key, selection.Equals, []string{val})
		if err != nil {
			return nil, err
		}
		selector = selector.Add(*req)
	}

	networkPolicyList, err := s.networkPolicyLister.NetworkPolicies(ch.Namespace).List(selector)
	if err != nil {
		return nil, err
	}

	var relevantNetworkPolicies []*networkingv1.NetworkPolicy
	for _, networkpolicy := range networkPolicyList {
		if !metav1.IsControlledBy(networkpolicy, ch) {
			logf.WithRelatedResource(log, networkpolicy).Info("found existing solver network policy for this challenge resource, however " +
				"it does not have an appropriate OwnerReference referencing this challenge. Skipping it altogether.")
			continue
		}
		relevantNetworkPolicies = append(relevantNetworkPolicies, networkpolicy)
	}

	return relevantNetworkPolicies, nil
}

// createNetworkPolicy will create the network policy required to solve this challenge
// in the target API server.
func (s *Solver) createNetworkPolicy(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (*networkingv1.NetworkPolicy, error) {
	np := buildNetworkPolicy(issuer, ch)
	return s.Client.NetworkingV1().NetworkPolicies(ch.Namespace).Create(np)
}

// buildNetworkPolicy builds a Network Policy object to allow any object to communicate with
// cm-acme-http-solver
func buildNetworkPolicy(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) *networkingv1.NetworkPolicy {
	podLabels := podLabels(ch)

	var protocol corev1.Protocol
	protocol = "TCP"

	port := intstr.FromInt(acmeSolverListenPort)

	networkpolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    "cm-acme-http-solver-",
			Namespace:       ch.Namespace,
			Labels:          podLabels,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podLabels,
			},
			PolicyTypes: []networkingv1.PolicyType{"Ingress"},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port:     &port,
							Protocol: &protocol,
						},
					},
				},
			},
		},
	}

	return networkpolicy
}

// cleanupNetworkPolicy will remove the network policies added to allow ingress controller
// to reach the cm-acme-http-solver
func (s *Solver) cleanupNetworkPolicy(ctx context.Context, ch *v1alpha1.Challenge) error {
	log := logf.FromContext(ctx, "cleanupNetworkPolicy")

	networkpolicies, err := s.getNetworkPoliciesForChallenge(ctx, ch)
	if err != nil {
		return err
	}
	var errs []error
	for _, networkpolicy := range networkpolicies {
		log := logf.WithRelatedResource(log, networkpolicy).V(logf.DebugLevel)
		log.Info("deleting network policy resource")
		log.Info("Namespace: %v", networkpolicy.Namespace)
		err := s.Client.NetworkingV1().NetworkPolicies(networkpolicy.Namespace).Delete(networkpolicy.Name, nil)

		if err != nil {
			log.Info("failed to delete network policy resource", "error", err)
			errs = append(errs, err)
			continue
		}
		log.Info("successfully deleted network policy resource")
	}
	return utilerrors.NewAggregate(errs)
}
