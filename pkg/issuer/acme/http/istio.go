/*
Copyright 2020 The Jetstack cert-manager contributors.

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

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	istioapinetworking "istio.io/api/networking/v1beta1"
	istioclientnetworking "istio.io/client-go/pkg/apis/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (s *Solver) ensureIstio(ctx context.Context, ch *cmacme.Challenge, svcName string) (bool *istioclientnetworking.VirtualService, err error) {
	log := logf.FromContext(ctx).WithName("ensureIstio")

	gateway, err := s.getGateway(ch)
	if err != nil {
		return nil, err
	}
	logf.WithRelatedResource(log, gateway).Info("found Gateway")

	virtualservice, err := s.getVirtualService(ctx, ch)
	if err != nil {
		return nil, err
	}

	if virtualservice == nil {
		log.Info("creating VirtualService")
		virtualservice, err = s.createVirtualService(ctx, ch, svcName, gateway)
		if err != nil {
			return nil, err
		}
		logf.WithRelatedResource(log, virtualservice).Info("VirtualService created successfully")
	} else {
		logf.WithRelatedResource(log, virtualservice).Info("found VirtualService")
	}

	virtualservice, err = s.checkAndUpdateVirtualService(ctx, ch, svcName, gateway, virtualservice)
	if err != nil {
		return nil, err
	}

	return virtualservice, nil
}

func (s *Solver) cleanupVirtualServices(_ context.Context, _ *cmacme.Challenge) error {
	// Nothing to do, GC will take care of deleting the VirtualServices when the Challenge is deleted
	return nil
}

func (s *Solver) getGateway(ch *cmacme.Challenge) (*istioclientnetworking.Gateway, error) {
	http01Istio := ch.Spec.Solver.HTTP01.Istio
	return s.gatewayLister.Gateways(http01Istio.GatewayNamespace).Get(http01Istio.GatewayName)
}

func (s *Solver) getVirtualService(ctx context.Context, ch *cmacme.Challenge) (*istioclientnetworking.VirtualService, error) {
	http01Istio := ch.Spec.Solver.HTTP01.Istio
	selector := labels.Set(podLabels(ch)).AsSelector()
	vsList, err := s.IstioClient.NetworkingV1beta1().VirtualServices(http01Istio.GatewayNamespace).
		List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, err
	}
	switch len(vsList.Items) {
	case 0:
		return nil, nil
	case 1:
		return &vsList.Items[0], nil
	default:
		// TODO delete all VirtualServices
		return nil, fmt.Errorf("multiple VirtualServices found")
	}
}

func (s *Solver) createVirtualService(ctx context.Context, ch *cmacme.Challenge, svcName string, gateway *istioclientnetworking.Gateway) (*istioclientnetworking.VirtualService, error) {
	vs := &istioclientnetworking.VirtualService{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    "cm-acme-http-solver-",
			Namespace:       gateway.Namespace,
			Labels:          podLabels(ch),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: createVirtualServiceSpec(ch, svcName, gateway),
	}
	return s.IstioClient.NetworkingV1beta1().VirtualServices(vs.Namespace).Create(ctx, vs, metav1.CreateOptions{})
}

func (s *Solver) checkAndUpdateVirtualService(ctx context.Context, ch *cmacme.Challenge, svcName string, gateway *istioclientnetworking.Gateway, virtualservice *istioclientnetworking.VirtualService) (*istioclientnetworking.VirtualService, error) {
	log := logf.FromContext(ctx, "checkAndUpdateVirtualService")

	needsUpdate := false

	expectedSpec := createVirtualServiceSpec(ch, svcName, gateway)
	if !reflect.DeepEqual(virtualservice.Spec, expectedSpec) {
		needsUpdate = true
		virtualservice.Spec = expectedSpec
	}

	if needsUpdate {
		logf.WithRelatedResource(log, virtualservice).Info("Updating VirtualService")
		return s.IstioClient.NetworkingV1beta1().VirtualServices(virtualservice.Namespace).Update(ctx, virtualservice, metav1.UpdateOptions{})
	}

	return virtualservice, nil
}

func createVirtualServiceSpec(ch *cmacme.Challenge, svcName string, gateway *istioclientnetworking.Gateway) istioapinetworking.VirtualService {
	ingPath := ingressPath(ch.Spec.Token, svcName)

	return istioapinetworking.VirtualService{
		ExportTo: []string{"*"},
		Hosts:    []string{ch.Spec.DNSName},
		Gateways: []string{gateway.Namespace + "/" + gateway.Name},
		Http: []*istioapinetworking.HTTPRoute{
			{
				Match: []*istioapinetworking.HTTPMatchRequest{
					{Uri: &istioapinetworking.StringMatch{MatchType: &istioapinetworking.StringMatch_Exact{Exact: ingPath.Path}}},
				},
				Route: []*istioapinetworking.HTTPRouteDestination{
					{
						Destination: &istioapinetworking.Destination{
							// TODO is ch.Namespace the correct namespace?
							Host: fmt.Sprintf("%s.%s.svc.cluster.local", ingPath.Backend.ServiceName, ch.Namespace),
							Port: &istioapinetworking.PortSelector{Number: acmeSolverListenPort},
						},
					},
				},
			},
		},
	}
}
