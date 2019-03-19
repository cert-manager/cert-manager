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
	"fmt"

	extv1beta1 "k8s.io/api/extensions/v1beta1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http/solver"
	"github.com/jetstack/cert-manager/pkg/util"
)

// getIngressesForChallenge returns a list of Ingresses that were created to solve
// http challenges for the given domain
func (s *Solver) getIngressesForChallenge(ch *v1alpha1.Challenge) ([]*extv1beta1.Ingress, error) {
	podLabels := podLabels(ch)
	selector := labels.NewSelector()
	for key, val := range podLabels {
		req, err := labels.NewRequirement(key, selection.Equals, []string{val})
		if err != nil {
			return nil, err
		}
		selector = selector.Add(*req)
	}

	klog.Infof("Looking up Ingresses for selector %v", selector)
	ingressList, err := s.ingressLister.Ingresses(ch.Namespace).List(selector)
	if err != nil {
		return nil, err
	}

	var relevantIngresses []*extv1beta1.Ingress
	for _, ingress := range ingressList {
		if !metav1.IsControlledBy(ingress, ch) {
			klog.Infof("Found ingress %q with acme-order-url annotation set to that of Challenge %q "+
				"but it is not owned by the Challenge resource, so skipping it.", ingress.Namespace+"/"+ingress.Name, ch.Namespace+"/"+ch.Name)
			continue
		}
		relevantIngresses = append(relevantIngresses, ingress)
	}

	return relevantIngresses, nil
}

// ensureIngress will ensure the ingress required to solve this challenge
// exists, or if an existing ingress is specified on the secret will ensure
// that the ingress has an appropriate challenge path configured
func (s *Solver) ensureIngress(ch *v1alpha1.Challenge, svcName string) (ing *extv1beta1.Ingress, err error) {
	httpDomainCfg := ch.Spec.Config.HTTP01
	if httpDomainCfg == nil {
		httpDomainCfg = &v1alpha1.HTTP01SolverConfig{}
	}
	if httpDomainCfg != nil &&
		httpDomainCfg.Ingress != "" {

		return s.addChallengePathToIngress(ch, svcName)
	}
	existingIngresses, err := s.getIngressesForChallenge(ch)
	if err != nil {
		return nil, err
	}
	if len(existingIngresses) == 1 {
		return existingIngresses[0], nil
	}
	if len(existingIngresses) > 1 {
		errMsg := fmt.Sprintf("multiple challenge solver ingresses found for Challenge '%s/%s'. Cleaning up existing pods.", ch.Namespace, ch.Name)
		klog.Infof(errMsg)
		err := s.cleanupIngresses(ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(errMsg)
	}

	klog.Infof("No existing HTTP01 challenge solver ingress found for Challenge %q. One will be created.", ch.Namespace+"/"+ch.Name)
	return s.createIngress(ch, svcName)
}

// createIngress will create a challenge solving pod for the given certificate,
// domain, token and key.
func (s *Solver) createIngress(ch *v1alpha1.Challenge, svcName string) (*extv1beta1.Ingress, error) {
	return s.Client.ExtensionsV1beta1().Ingresses(ch.Namespace).Create(buildIngressResource(ch, svcName))
}

func buildIngressResource(ch *v1alpha1.Challenge, svcName string) *extv1beta1.Ingress {
	var ingClass *string
	if ch.Spec.Config.HTTP01 != nil {
		ingClass = ch.Spec.Config.HTTP01.IngressClass
	}

	podLabels := podLabels(ch)
	// TODO: add additional annotations to help workaround problematic ingress controller behaviours
	ingAnnotations := make(map[string]string)
	ingAnnotations["nginx.ingress.kubernetes.io/whitelist-source-range"] = "0.0.0.0/0"

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
	}
}

func (s *Solver) addChallengePathToIngress(ch *v1alpha1.Challenge, svcName string) (*extv1beta1.Ingress, error) {
	ingressName := ch.Spec.Config.HTTP01.Ingress

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
			rule.HTTP.Paths = append(rule.HTTP.Paths, ingPathToAdd)
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
func (s *Solver) cleanupIngresses(ch *v1alpha1.Challenge) error {
	httpDomainCfg := ch.Spec.Config.HTTP01
	if httpDomainCfg == nil {
		httpDomainCfg = &v1alpha1.HTTP01SolverConfig{}
	}
	existingIngressName := httpDomainCfg.Ingress

	// if the 'ingress' field on the domain config is not set, we need to delete
	// the ingress resources that cert-manager has created to solve the challenge
	if existingIngressName == "" {
		ingresses, err := s.getIngressesForChallenge(ch)
		if err != nil {
			return err
		}
		klog.V(4).Infof("Found %d ingresses to clean up for certificate %q", len(ingresses), ch.Namespace+"/"+ch.Name)
		var errs []error
		for _, ingress := range ingresses {
			// TODO: should we call DeleteCollection here? We'd need to somehow
			// also ensure ownership as part of that request using a FieldSelector.
			err := s.Client.ExtensionsV1beta1().Ingresses(ingress.Namespace).Delete(ingress.Name, nil)
			if err != nil {
				errs = append(errs, err)
			}
		}
		return utilerrors.NewAggregate(errs)
	}

	// otherwise, we need to remove any cert-manager added rules from the ingress resource
	ing, err := s.Client.ExtensionsV1beta1().Ingresses(ch.Namespace).Get(existingIngressName, metav1.GetOptions{})
	if k8sErrors.IsNotFound(err) {
		klog.Infof("attempt to cleanup Ingress %q of ACME challenge path failed: %v", ch.Namespace+"/"+existingIngressName, err)
		return nil
	}
	if err != nil {
		return err
	}

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
