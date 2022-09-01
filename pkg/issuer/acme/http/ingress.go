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

package http

import (
	"context"
	"fmt"
	"net"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/http/solver"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	// annotationIngressClass is the well-known annotation key
	// for specifying ingress classes. It is currently not specified
	// in the networking/v1 package, so it is duplicated here
	// to avoid an extra import of networking/v1beta1.
	annotationIngressClass = "kubernetes.io/ingress.class"
)

// getIngressesForChallenge returns a list of Ingresses that were created to solve
// http challenges for the given domain
func (s *Solver) getIngressesForChallenge(ctx context.Context, ch *cmacme.Challenge) ([]*networkingv1.Ingress, error) {
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

	var relevantIngresses []*networkingv1.Ingress
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
func (s *Solver) ensureIngress(ctx context.Context, ch *cmacme.Challenge, svcName string) (ing *networkingv1.Ingress, err error) {
	log := logf.FromContext(ctx).WithName("ensureIngress")
	httpDomainCfg, err := http01IngressCfgForChallenge(ch)
	if err != nil {
		return nil, err
	}
	if httpDomainCfg.Name != "" {
		log := logf.WithRelatedResourceName(log, httpDomainCfg.Name, ch.Namespace, "Ingress")
		ctx := logf.NewContext(ctx, log)
		log.V(logf.DebugLevel).Info("adding solver paths to existing ingress resource")
		return s.addChallengePathToIngress(ctx, ch, svcName)
	}
	existingIngresses, err := s.getIngressesForChallenge(ctx, ch)
	if err != nil {
		return nil, err
	}
	if len(existingIngresses) == 1 && ingressServiceName(existingIngresses[0]) == svcName {
		logf.WithRelatedResource(log, existingIngresses[0]).Info("found one existing HTTP01 solver ingress")
		return existingIngresses[0], nil
	}
	if len(existingIngresses) == 1 && ingressServiceName(existingIngresses[0]) != svcName {
		log.V(logf.DebugLevel).Info("service name changed. cleaning up all existing ingresses.")
		err := s.cleanupIngresses(ctx, ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("service name changed, existing challenge solver ingresses found and cleaned up. retrying challenge sync")
	}
	if len(existingIngresses) > 1 {
		log.V(logf.InfoLevel).Info("multiple challenge solver ingresses found for challenge. cleaning up all existing ingresses.")
		err := s.cleanupIngresses(ctx, ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("multiple existing challenge solver ingresses found and cleaned up. retrying challenge sync")
	}

	log.V(logf.DebugLevel).Info("creating HTTP01 challenge solver ingress")
	return s.createIngress(ctx, ch, svcName)
}

func ingressServiceName(ing *networkingv1.Ingress) string {
	return ing.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name
}

// createIngress will create a challenge solving ingress for the given certificate,
// domain, token and key.
func (s *Solver) createIngress(ctx context.Context, ch *cmacme.Challenge, svcName string) (*networkingv1.Ingress, error) {
	ing, err := buildIngressResource(ch, svcName)
	if err != nil {
		return nil, err
	}

	// Override the defaults if they have changed in the ingress template.
	if ch.Spec.Solver.HTTP01 != nil &&
		ch.Spec.Solver.HTTP01.Ingress != nil {
		ing = s.mergeIngressObjectMetaWithIngressResourceTemplate(ing, ch.Spec.Solver.HTTP01.Ingress.IngressTemplate)
	}

	return s.Client.NetworkingV1().Ingresses(ch.Namespace).Create(ctx, ing, metav1.CreateOptions{})
}

func buildIngressResource(ch *cmacme.Challenge, svcName string) (*networkingv1.Ingress, error) {
	http01IngressCfg, err := http01IngressCfgForChallenge(ch)
	if err != nil {
		return nil, err
	}

	podLabels := podLabels(ch)

	ingAnnotations := make(map[string]string)

	// TODO: Figure out how to remove this without breaking users who depend on it.
	ingAnnotations["nginx.ingress.kubernetes.io/whitelist-source-range"] = "0.0.0.0/0,::/0"

	// Use the Ingress Class annotation defined in networkingv1beta1 even though our Ingress objects
	// are networkingv1, for maximum compatibility with all Ingress controllers.
	// if the `kubernetes.io/ingress.class` annotation is present, it takes precedence over the
	// `spec.IngressClassName` field.
	// See discussion in https://github.com/cert-manager/cert-manager/issues/4537.
	if http01IngressCfg.Class != nil {
		ingAnnotations[annotationIngressClass] = *http01IngressCfg.Class
	}

	ingPathToAdd := ingressPath(ch.Spec.Token, svcName)

	httpHost := ch.Spec.DNSName
	// if we need to verify ownership of an IP the challenge should propagate on all hosts
	if net.ParseIP(httpHost) != nil {
		httpHost = ""
	}
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    "cm-acme-http-solver-",
			Namespace:       ch.Namespace,
			Labels:          podLabels,
			Annotations:     ingAnnotations,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: networkingv1.IngressSpec{
			// https://github.com/cert-manager/cert-manager/issues/4537
			IngressClassName: nil,
			Rules: []networkingv1.IngressRule{
				{
					Host: httpHost,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								ingPathToAdd,
							},
						},
					},
				},
			},
		},
	}, nil
}

// Merge object meta from the ingress template. Fall back to default values.
func (s *Solver) mergeIngressObjectMetaWithIngressResourceTemplate(ingress *networkingv1.Ingress, ingressTempl *cmacme.ACMEChallengeSolverHTTP01IngressTemplate) *networkingv1.Ingress {
	if ingressTempl == nil {
		return ingress
	}

	if ingress.Labels == nil {
		ingress.Labels = make(map[string]string)
	}

	for k, v := range ingressTempl.Labels {
		ingress.Labels[k] = v
	}

	if ingress.Annotations == nil {
		ingress.Annotations = make(map[string]string)
	}

	for k, v := range ingressTempl.Annotations {
		// check if the user set the whitelist-source-range annotation in the template
		annotation := k[strings.LastIndex(k, "/")+1:]
		if annotation == "whitelist-source-range" {
			delete(ingress.Annotations, "nginx.ingress.kubernetes.io/whitelist-source-range")
		}
		ingress.Annotations[k] = v
	}

	return ingress
}

func (s *Solver) addChallengePathToIngress(ctx context.Context, ch *cmacme.Challenge, svcName string) (*networkingv1.Ingress, error) {
	httpDomainCfg, err := http01IngressCfgForChallenge(ch)
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
				rule.HTTP = &networkingv1.HTTPIngressRuleValue{}
			}
			for i, p := range rule.HTTP.Paths {
				// if an existing path exists on this rule for the challenge path,
				// we overwrite it else we'll confuse ingress controllers
				if p.Path == ingPathToAdd.Path {
					// ingress resource is already up to date
					if p.Backend.Service.Name == ingPathToAdd.Backend.Service.Name &&
						p.Backend.Service.Port == ingPathToAdd.Backend.Service.Port {
						return ing, nil
					}
					rule.HTTP.Paths[i] = ingPathToAdd
					return s.Client.NetworkingV1().Ingresses(ing.Namespace).Update(ctx, ing, metav1.UpdateOptions{})
				}
			}
			rule.HTTP.Paths = append([]networkingv1.HTTPIngressPath{ingPathToAdd}, rule.HTTP.Paths...)
			return s.Client.NetworkingV1().Ingresses(ing.Namespace).Update(ctx, ing, metav1.UpdateOptions{})
		}
	}

	// if one doesn't exist, create a new IngressRule
	ing.Spec.Rules = append(ing.Spec.Rules, networkingv1.IngressRule{
		Host: ch.Spec.DNSName,
		IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{ingPathToAdd},
			},
		},
	})
	return s.Client.NetworkingV1().Ingresses(ing.Namespace).Update(ctx, ing, metav1.UpdateOptions{})
}

// cleanupIngresses will remove the rules added by cert-manager to an existing
// ingress, or delete the ingress if an existing ingress name is not specified
// on the certificate.
func (s *Solver) cleanupIngresses(ctx context.Context, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx, "cleanupIngresses")

	if ch.Spec.Solver.HTTP01.Ingress == nil {
		return nil
	}

	httpDomainCfg, err := http01IngressCfgForChallenge(ch)
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

			log.V(logf.DebugLevel).Info("deleting ingress resource")
			err := s.Client.NetworkingV1().Ingresses(ingress.Namespace).Delete(ctx, ingress.Name, metav1.DeleteOptions{})
			if err != nil {
				log.V(logf.WarnLevel).Info("failed to delete ingress resource", "error", err)
				errs = append(errs, err)
				continue
			}
			log.V(logf.DebugLevel).Info("successfully deleted ingress resource")
		}
		return utilerrors.NewAggregate(errs)
	}

	// otherwise, we need to remove any cert-manager added rules from the ingress resource
	ing, err := s.Client.NetworkingV1().Ingresses(ch.Namespace).Get(ctx, existingIngressName, metav1.GetOptions{})
	if k8sErrors.IsNotFound(err) {
		log.Error(err, "named ingress resource not found, skipping cleanup")
		return nil
	}
	if err != nil {
		return err
	}
	log = logf.WithRelatedResource(log, ing)

	log.V(logf.DebugLevel).Info("attempting to clean up automatically added solver paths on ingress resource")
	ingPathToDel := solverPathFn(ch.Spec.Token)
	var ingRules []networkingv1.IngressRule
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
				log.V(logf.DebugLevel).Info("deleting challenge solver path on ingress resource", "host", rule.Host, "path", path.Path)
				rule.HTTP.Paths = append(rule.HTTP.Paths[:i], rule.HTTP.Paths[i+1:]...)
			}
		}

		// if there are still paths level on this rule, we should retain it
		if len(rule.HTTP.Paths) > 0 {
			ingRules = append(ingRules, rule)
		}
	}

	ing.Spec.Rules = ingRules

	_, err = s.Client.NetworkingV1().Ingresses(ing.Namespace).Update(ctx, ing, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	log.V(logf.DebugLevel).Info("cleaned up all challenge solver paths on ingress resource")

	return nil
}

// ingressPath returns the ingress HTTPIngressPath object needed to solve this
// challenge.
func ingressPath(token, serviceName string) networkingv1.HTTPIngressPath {
	return networkingv1.HTTPIngressPath{
		Path:     solverPathFn(token),
		PathType: func() *networkingv1.PathType { s := networkingv1.PathTypeImplementationSpecific; return &s }(),
		Backend: networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: serviceName,
				Port: networkingv1.ServiceBackendPort{
					Number: acmeSolverListenPort,
				},
			},
		},
	}
}

var solverPathFn = func(token string) string {
	return fmt.Sprintf("%s/%s", solver.HTTPChallengePath, token)
}
