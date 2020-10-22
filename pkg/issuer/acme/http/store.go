package http

import (
	"context"

	"github.com/davecgh/go-spew/spew"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/http/convertlister"

	networkingv1beta1 "k8s.io/api/networking/v1beta1"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *Solver) GetIngress(namespace string, name string) (*networkingv1.Ingress, error) {
	if s.apiVersion == networkingv1.SchemeGroupVersion {
		return s.Client.NetworkingV1().Ingresses(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	} else if s.apiVersion == networkingv1beta1.SchemeGroupVersion {
		olderIngress, err := s.Client.NetworkingV1beta1().Ingresses(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		newerIngress := networkingv1.Ingress{}
		convertlister.ConvertNetworkingV1beta1ToNetworkingV1Ingress(olderIngress, &newerIngress)
		return &newerIngress, nil
	}

	// fallback to extensionsv1beta1 ingress
	// TODO

	return nil, nil
}

func (s *Solver) CreateIngress(namespace string, ing *networkingv1.Ingress) (*networkingv1.Ingress, error) {
	if s.apiVersion == networkingv1.SchemeGroupVersion {
		return s.Client.NetworkingV1().Ingresses(namespace).Create(context.TODO(), ing, metav1.CreateOptions{})
	} else if s.apiVersion == networkingv1beta1.SchemeGroupVersion {
		olderIngress := networkingv1beta1.Ingress{}
		convertlister.ConvertNetworkingV1ToNetworkingV1beta1Ingress(ing, &olderIngress)

		spew.Dump(olderIngress)

		resp, err := s.Client.NetworkingV1beta1().Ingresses(namespace).Create(context.TODO(), &olderIngress, metav1.CreateOptions{})

		newerIngress := networkingv1.Ingress{}
		convertlister.ConvertNetworkingV1beta1ToNetworkingV1Ingress(resp, &newerIngress)

		return &newerIngress, err
	}

	// fallback to extensionsv1beta1 ingress
	// TODO

	return nil, nil
}

func (s *Solver) UpdateIngress(namespace string, ing *networkingv1.Ingress) (*networkingv1.Ingress, error) {
	if s.apiVersion == networkingv1.SchemeGroupVersion {
		return s.Client.NetworkingV1().Ingresses(namespace).Update(context.TODO(), ing, metav1.UpdateOptions{})
	} else if s.apiVersion == networkingv1beta1.SchemeGroupVersion {
		olderIngress := networkingv1beta1.Ingress{}
		convertlister.ConvertNetworkingV1ToNetworkingV1beta1Ingress(ing, &olderIngress)
		_, err := s.Client.NetworkingV1beta1().Ingresses(namespace).Update(context.TODO(), &olderIngress, metav1.UpdateOptions{})
		return ing, err
	}

	// fallback to extensionsv1beta1 ingress
	// TODO

	return nil, nil
}
