/*
Copyright 2021 The cert-manager Authors.

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
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// ensureGatewayHTTPRoute ensures that the HTTPRoutes needed to solve a challenge exist.
func (s *Solver) ensureGatewayHTTPRoute(ctx context.Context, ch *cmacme.Challenge, svcName string) (*gwapi.HTTPRoute, error) {
	if ch == nil {
		return nil, fmt.Errorf("ensureGatewayHTTPRoute received nil *acme.Challenge")
	}
	log := logf.FromContext(ctx).WithName("ensureGatewayHTTPRoute")

	httpRoute, err := s.getGatewayHTTPRoute(ctx, ch)
	if err != nil {
		return nil, err
	}

	if httpRoute == nil {
		log.Info("creating HTTPRoute for challenge", "name", ch.Name, "namespace", ch.Namespace)
		httpRoute, err = s.createGatewayHTTPRoute(ctx, ch, svcName)
		if err != nil {
			return nil, err
		}
		return httpRoute, nil
	}

	log.Info("Found existing HTTPRoute for challenge", "name", ch.Name, "namespace", ch.Namespace)

	httpRoute, err = s.checkAndUpdateGatewayHTTPRoute(ctx, ch, svcName, httpRoute)
	if err != nil {
		return nil, err
	}

	return httpRoute, nil
}

func (s *Solver) getGatewayHTTPRoute(ctx context.Context, ch *cmacme.Challenge) (*gwapi.HTTPRoute, error) {
	log := logf.FromContext(ctx).WithName("getGatewayHTTPRoute")
	log.Info("getting httpRoutes for challenge", "name", ch.Name, "namespace", ch.Namespace)
	httpRoutes, err := s.httpRouteLister.HTTPRoutes(ch.Namespace).List(labels.Set(podLabels(ch)).AsSelector())
	if err != nil {
		return nil, err
	}
	switch len(httpRoutes) {
	case 0:
		return nil, nil
	case 1:
		return httpRoutes[0], nil
	default:
		// It should not be possible for multiple HTTPRoutes for this challenge to exist
		// If we find this, try to delete them.
		for _, httpRoute := range httpRoutes[1:] {
			log.Info("Deleting extra HTTPRoute", "name", httpRoute.Name, "namespace", httpRoute.Namespace)
			err := s.GWClient.GatewayV1().HTTPRoutes(httpRoute.Namespace).Delete(ctx, httpRoute.Name, metav1.DeleteOptions{})
			if err != nil {
				return nil, err
			}
		}
		return nil, fmt.Errorf("multiple HTTPRoutes found")
	}
}

func (s *Solver) createGatewayHTTPRoute(ctx context.Context, ch *cmacme.Challenge, svcName string) (*gwapi.HTTPRoute, error) {
	labels := podLabels(ch)
	for k, v := range ch.Spec.Solver.HTTP01.GatewayHTTPRoute.Labels {
		labels[k] = v
	}
	httpRoute := &gwapi.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    "cm-acme-http-solver-",
			Namespace:       ch.Namespace,
			Labels:          labels,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: generateHTTPRouteSpec(ch, svcName),
	}
	newHTTPRoute, err := s.GWClient.GatewayV1().HTTPRoutes(ch.Namespace).Create(ctx, httpRoute, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return newHTTPRoute, nil
}

func (s *Solver) checkAndUpdateGatewayHTTPRoute(ctx context.Context, ch *cmacme.Challenge, svcName string, httpRoute *gwapi.HTTPRoute) (*gwapi.HTTPRoute, error) {
	log := logf.FromContext(ctx, "checkAndUpdateGatewayHTTPRoute")
	expectedSpec := generateHTTPRouteSpec(ch, svcName)
	actualSpec := httpRoute.Spec
	expectedLabels := podLabels(ch)
	for k, v := range ch.Spec.Solver.HTTP01.GatewayHTTPRoute.Labels {
		expectedLabels[k] = v
	}
	actualLabels := httpRoute.Labels
	if reflect.DeepEqual(expectedSpec, actualSpec) && reflect.DeepEqual(expectedLabels, actualLabels) {
		return httpRoute, nil
	}
	log.Info("HTTPRoute is out of date, updating", "name", httpRoute.Name, "namespace", httpRoute.Namespace)
	var ret *gwapi.HTTPRoute
	var err error
	if err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		oldHTTPRoute, err := s.GWClient.GatewayV1().HTTPRoutes(httpRoute.Namespace).Get(ctx, httpRoute.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		newHTTPRoute := oldHTTPRoute.DeepCopy()
		newHTTPRoute.Spec = expectedSpec
		newHTTPRoute.Labels = expectedLabels
		ret, err = s.GWClient.GatewayV1().HTTPRoutes(newHTTPRoute.Namespace).Update(ctx, newHTTPRoute, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

func generateHTTPRouteSpec(ch *cmacme.Challenge, svcName string) gwapi.HTTPRouteSpec {
	return gwapi.HTTPRouteSpec{
		CommonRouteSpec: gwapi.CommonRouteSpec{
			ParentRefs: ch.Spec.Solver.HTTP01.GatewayHTTPRoute.ParentRefs,
		},
		Hostnames: []gwapi.Hostname{
			gwapi.Hostname(ch.Spec.DNSName),
		},
		Rules: []gwapi.HTTPRouteRule{
			{
				Matches: []gwapi.HTTPRouteMatch{
					{
						Path: &gwapi.HTTPPathMatch{
							Type:  func() *gwapi.PathMatchType { p := gwapi.PathMatchExact; return &p }(),
							Value: ptr.To(fmt.Sprintf("/.well-known/acme-challenge/%s", ch.Spec.Token)),
						},
					},
				},
				BackendRefs: []gwapi.HTTPBackendRef{
					{
						BackendRef: gwapi.BackendRef{
							BackendObjectReference: gwapi.BackendObjectReference{
								Group:     func() *gwapi.Group { g := gwapi.Group(""); return &g }(),
								Kind:      func() *gwapi.Kind { k := gwapi.Kind("Service"); return &k }(),
								Name:      gwapi.ObjectName(svcName),
								Namespace: func() *gwapi.Namespace { n := gwapi.Namespace(ch.Namespace); return &n }(),
								Port:      func() *gwapi.PortNumber { p := gwapi.PortNumber(acmeSolverListenPort); return &p }(),
							},
							Weight: ptr.To(int32(1)),
						},
					},
				},
			},
		},
	}
}
