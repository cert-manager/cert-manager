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

	extv1beta1 "k8s.io/api/extensions/v1beta1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http/solver"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util"
)

// getIngressesForChallenge returns a list of Ingresses that were created to solve
// http challenges for the given domain
func (s *Solver) getIngressesForChallenge(ctx context.Context, ch *v1alpha1.Challenge) ([]*extv1beta1.Ingress, error) {
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

	log.V(logf.DebugLevel).Info("checking for existing HTTP01 solver ingresses")
	ingressList, err := s.ingressLister.Ingresses(ch.Namespace).List(selector)
	if err != nil {
		return nil, err
	}

	var relevantIngresses []*extv1beta1.Ingress
	for _, ingress := range ingressList {
		if !metav1.IsControlledBy(ingress, ch) {
			logf.WithRelatedResource(log, ingress).Info("found existing solver ingress for this challenge resource, however " +
				"it does not have an appropriate OwnerReference referencing this challenge. Skipping it altogether.")
			continue
		}
		relevantIngresses = append(relevantIngresses, ingress)
	}

	return relevantIngresses, nil
}

// ensureIngress will ensure the ingress required to solve this challenge
// exists, or if an existing ingress is specified on the secret will ensure
// that the ingress has an appropriate challenge path configured
func (s *Solver) ensureIngress(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, svcName string) (ing *extv1beta1.Ingress, err error) {
	log := logf.FromContext(ctx).WithName("ensureIngress")
	httpDomainCfg, err := httpDomainCfgForChallenge(issuer, ch)
	if err != nil {
		return nil, err
	}
	if httpDomainCfg.Name != "" {
		log := logf.WithRelatedResourceName(log, httpDomainCfg.Name, ch.Namespace, "Ingress")
		ctx := logf.NewContext(ctx, log)
		log.Info("adding solver paths to existing ingress resource")
		return s.addChallengePathToIngress(ctx, issuer, ch, svcName)
	}
	existingIngresses, err := s.getIngressesForChallenge(ctx, ch)
	if err != nil {
		return nil, err
	}
	if len(existingIngresses) == 1 {
		logf.WithRelatedResource(log, existingIngresses[0]).Info("found one existing HTTP01 solver ingress")
		return existingIngresses[0], nil
	}
	if len(existingIngresses) > 1 {
		log.Info("multiple challenge solver ingresses found for challenge. cleaning up all existing ingresses.")
		err := s.cleanupIngresses(ctx, issuer, ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("multiple existing challenge solver ingresses found and cleaned up. retrying challenge sync")
	}

	log.Info("creating HTTP01 challenge solver ingress")
	return s.createIngress(issuer, ch, svcName)
}

// createIngress will create a challenge solving pod for the given certificate,
// domain, token and key.
func (s *Solver) createIngress(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, svcName string) (*extv1beta1.Ingress, error) {
	ing, err := buildIngressResource(issuer, ch, svcName)
	if err != nil {
		return nil, err
	}
	return s.Client.ExtensionsV1beta1().Ingresses(ch.Namespace).Create(ing)
}

func buildIngressResource(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, svcName string) (*extv1beta1.Ingress, error) {
	httpDomainCfg, err := httpDomainCfgForChallenge(issuer, ch)
	if err != nil {
		return nil, err
	}
	var ingClass *string
	if httpDomainCfg.Class != nil {
		ingClass = httpDomainCfg.Class
	}

	podLabels := podLabels(ch)
	// TODO: add additional annotations to help workaround problematic ingress controller behaviours
	ingAnnotations := make(map[string]string)
	ingAnnotations["nginx.ingress.kubernetes.io/whitelist-source-range"] = "0.0.0.0/0,::/0"

	if ingClass != nil {
		ingAnnotations[util.IngressKey] = *ingClass
	}

	ingPathToAdd := ingressPath(ch.Spec.Token, svcName)

	return &extv1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    "cm-acme-http-solver-",
			Namespace:       ch.Namespace,
			Labels:          podLabels,
			Annotations:     ingAnnotations,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: extv1beta1.IngressSpec{
			Rules: []extv1beta1.IngressRule{
				{
					Host: ch.Spec.DNSName,
					IngressRuleValue: extv1beta1.IngressRuleValue{
						HTTP: &extv1beta1.HTTPIngressRuleValue{
							Paths: []extv1beta1.HTTPIngressPath{ingPathToAdd},
						},
					},
				},
			},
		},
	}, nil
}

func (s *Solver) addChallengePathToIngress(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, svcName string) (*extv1beta1.Ingress, error) {
	httpDomainCfg, err := httpDomainCfgForChallenge(issuer, ch)
	if err != nil {
		return nil, err
	}
	ingressName := httpDomainCfg.Name

	ing, err := s.ingressLister.Ingresses(ch.Namespace).Get(ingressName)
	if err != nil {
		return nil, err
	}

	ingPathToAdd := ingressPath(ch.Spec.Token, svcName)
	// check for an existing Rule for the given domain on the ingress resource
	for _, rule := range ing.Spec.Rules {
		if rule.Host == ch.Spec.DNSName {
			if rule.HTTP == nil {
				rule.HTTP = &extv1beta1.HTTPIngressRuleValue{}
			}
			for i, p := range rule.HTTP.Paths {
				// if an existing path exists on this rule for the challenge path,
				// we overwrite it else we'll confuse ingress controllers
				if p.Path == ingPathToAdd.Path {
					// ingress resource is already up to date
					if p.Backend.ServiceName == ingPathToAdd.Backend.ServiceName &&
						p.Backend.ServicePort == ingPathToAdd.Backend.ServicePort {
						return ing, nil
					}
					rule.HTTP.Paths[i] = ingPathToAdd
					return s.Client.ExtensionsV1beta1().Ingresses(ing.Namespace).Update(ing)
				}
			}
			rule.HTTP.Paths = append([]extv1beta1.HTTPIngressPath{ingPathToAdd}, rule.HTTP.Paths...)
			return s.Client.ExtensionsV1beta1().Ingresses(ing.Namespace).Update(ing)
		}
	}

	// if one doesn't exist, create a new IngressRule
	ing.Spec.Rules = append(ing.Spec.Rules, extv1beta1.IngressRule{
		Host: ch.Spec.DNSName,
		IngressRuleValue: extv1beta1.IngressRuleValue{
			HTTP: &extv1beta1.HTTPIngressRuleValue{
				Paths: []extv1beta1.HTTPIngressPath{ingPathToAdd},
			},
		},
	})
	return s.Client.ExtensionsV1beta1().Ingresses(ing.Namespace).Update(ing)
}

// cleanupIngresses will remove the rules added by cert-manager to an existing
// ingress, or delete the ingress if an existing ingress name is not specified
// on the certificate.
func (s *Solver) cleanupIngresses(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	log := logf.FromContext(ctx, "cleanupPods")

	httpDomainCfg, err := httpDomainCfgForChallenge(issuer, ch)
	if err != nil {
		return err
	}
	existingIngressName := httpDomainCfg.Name

	// if the 'ingress' field on the domain config is not set, we need to delete
	// the ingress resources that cert-manager has created to solve the challenge
	if existingIngressName == "" {
		ingresses, err := s.getIngressesForChallenge(ctx, ch)
		if err != nil {
			return err
		}
		var errs []error
		for _, ingress := range ingresses {
			log := logf.WithRelatedResource(log, ingress).V(logf.DebugLevel)

			log.Info("deleting ingress resource")
			err := s.Client.ExtensionsV1beta1().Ingresses(ingress.Namespace).Delete(ingress.Name, nil)
			if err != nil {
				log.Info("failed to delete ingress resource", "error", err)
				errs = append(errs, err)
				continue
			}
			log.Info("successfully deleted ingress resource")
		}
		return utilerrors.NewAggregate(errs)
	}

	// otherwise, we need to remove any cert-manager added rules from the ingress resource
	ing, err := s.Client.ExtensionsV1beta1().Ingresses(ch.Namespace).Get(existingIngressName, metav1.GetOptions{})
	if k8sErrors.IsNotFound(err) {
		log.Error(err, "named ingress resource not found, skipping cleanup")
		return nil
	}
	if err != nil {
		return err
	}
	log = logf.WithRelatedResource(log, ing)

	log.Info("attempting to clean up automatically added solver paths on ingress resource")
	ingPathToDel := solverPathFn(ch.Spec.Token)
	var ingRules []extv1beta1.IngressRule
	for _, rule := range ing.Spec.Rules {
		// always retain rules that are not for the same DNSName
		if rule.Host != ch.Spec.DNSName {
			ingRules = append(ingRules, rule)
			continue
		}

		// always retain rules that don't specify `HTTP`
		if rule.HTTP == nil {
			ingRules = append(ingRules, rule)
			continue
		}

		// check the rule for paths. If we find the ingress path we need to
		// delete here, delete it
		for i, path := range rule.HTTP.Paths {
			if path.Path == ingPathToDel {
				log.Info("deleting challenge solver path on ingress resource", "host", rule.Host, "path", path.Path)
				rule.HTTP.Paths = append(rule.HTTP.Paths[:i], rule.HTTP.Paths[i+1:]...)
			}
		}

		// if there are still paths level on this rule, we should retain it
		if len(rule.HTTP.Paths) > 0 {
			ingRules = append(ingRules, rule)
		}
	}

	ing.Spec.Rules = ingRules

	_, err = s.Client.ExtensionsV1beta1().Ingresses(ing.Namespace).Update(ing)
	if err != nil {
		return err
	}

	log.Info("cleaned up all challenge solver paths on ingress resource")

	return nil
}

// ingressPath returns the ingress HTTPIngressPath object needed to solve this
// challenge.
func ingressPath(token, serviceName string) extv1beta1.HTTPIngressPath {
	return extv1beta1.HTTPIngressPath{
		Path: solverPathFn(token),
		Backend: extv1beta1.IngressBackend{
			ServiceName: serviceName,
			ServicePort: intstr.FromInt(acmeSolverListenPort),
		},
	}
}

var solverPathFn = func(token string) string {
	return fmt.Sprintf("%s/%s", solver.HTTPChallengePath, token)
}
