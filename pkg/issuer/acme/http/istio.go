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

	networkingv1beta1 "istio.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	"github.com/jetstack/cert-manager/pkg/internal/istio"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

func (s *Solver) ensureIstio(ctx context.Context, ch *cmacme.Challenge, svcName string) (*istio.VirtualService, error) {
	log := logf.FromContext(ctx).WithName("ensureIstio")

	virtualService, err := s.getVirtualService(ctx, ch)
	if err != nil {
		return nil, err
	}

	if virtualService == nil {
		log.Info("creating VirtualService")
		virtualService, err = s.createVirtualService(ctx, ch, svcName)
		if err != nil {
			return nil, err
		}
		log.Info("created VirtualService successfully")

		return virtualService, nil
	}

	log.Info("found VirtualService")

	virtualService, err = s.checkAndUpdateVirtualService(ctx, ch, svcName, virtualService)
	if err != nil {
		return nil, err
	}

	return virtualService, nil
}

func (s *Solver) cleanupVirtualServices(_ context.Context, _ *cmacme.Challenge) error {
	// Nothing to do, GC will take care of deleting the VirtualServices when the Challenge is deleted
	return nil
}

func (s *Solver) getVirtualService(ctx context.Context, ch *cmacme.Challenge) (*istio.VirtualService, error) {
	log := logf.FromContext(ctx, "getVirtualService")

	selector := labels.Set(podLabels(ch)).AsSelector()
	vsList, err := s.virtualServiceLister.Namespace(ch.Namespace).List(selector)
	if err != nil {
		return nil, err
	}
	switch len(vsList) {
	case 0:
		return nil, nil
	case 1:
		virtualService, err := istio.VirtualServiceFromUnstructured(vsList[0])
		if err != nil {
			return nil, err
		}
		return virtualService, nil
	default:
		for _, vs := range vsList[1:] {
			log.Info("deleting VirtualService")
			err := s.DynamicClient.Resource(istio.VirtualServiceGvr()).Namespace(ch.Namespace).Delete(ctx, vs.GetName(), metav1.DeleteOptions{})
			if err != nil {
				return nil, err
			}
		}
		return nil, fmt.Errorf("multiple VirtualServices found")
	}
}

func (s *Solver) createVirtualService(ctx context.Context, ch *cmacme.Challenge, svcName string) (*istio.VirtualService, error) {
	expectedSpec := createVirtualServiceSpec(ch, svcName)

	vs := istio.VirtualService{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    "cm-acme-http-solver-",
			Namespace:       ch.Namespace,
			Labels:          podLabels(ch),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: *expectedSpec,
	}

	unstr, err := vs.ToUnstructured()
	if err != nil {
		return nil, err
	}
	val, err := s.DynamicClient.Resource(istio.VirtualServiceGvr()).Namespace(ch.Namespace).Create(ctx, unstr, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	virtualService, err := istio.VirtualServiceFromUnstructured(val)
	if err != nil {
		return nil, err
	}
	return virtualService, nil
}

func (s *Solver) checkAndUpdateVirtualService(ctx context.Context, ch *cmacme.Challenge, svcName string, virtualservice *istio.VirtualService) (*istio.VirtualService, error) {
	log := logf.FromContext(ctx, "checkAndUpdateVirtualService")

	expectedSpec := createVirtualServiceSpec(ch, svcName)

	spec := &virtualservice.Spec
	if reflect.DeepEqual(spec, expectedSpec) {
		return virtualservice, nil
	}

	log.Info("updating VirtualService")

	virtualservice.Spec = *expectedSpec
	unstr, err := virtualservice.ToUnstructured()
	if err != nil {
		return nil, err
	}
	val, err := s.DynamicClient.Resource(istio.VirtualServiceGvr()).Namespace(ch.Namespace).Update(ctx, unstr, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	virtualService, err := istio.VirtualServiceFromUnstructured(val)
	if err != nil {
		return nil, err
	}
	return virtualService, nil
}

func createVirtualServiceSpec(ch *cmacme.Challenge, svcName string) *networkingv1beta1.VirtualService {
	http01Istio := ch.Spec.Solver.HTTP01.Istio

	return &networkingv1beta1.VirtualService{
		ExportTo: []string{"*"},
		Hosts:    []string{ch.Spec.DNSName},
		Gateways: http01Istio.Gateways,
		Http: []*networkingv1beta1.HTTPRoute{
			{
				Match: []*networkingv1beta1.HTTPMatchRequest{
					{Uri: &networkingv1beta1.StringMatch{MatchType: &networkingv1beta1.StringMatch_Exact{Exact: solverPathFn(ch.Spec.Token)}}},
				},
				Route: []*networkingv1beta1.HTTPRouteDestination{
					{
						Destination: &networkingv1beta1.Destination{
							Host: svcName,
							Port: &networkingv1beta1.PortSelector{Number: acmeSolverListenPort},
						},
					},
				},
			},
		},
	}
}
