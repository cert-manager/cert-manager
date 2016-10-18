package service

import (
	"fmt"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"

	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sErrors "k8s.io/kubernetes/pkg/api/errors"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
)

var _ kubelego.Service = &Service{}

type Service struct {
	ServiceApi *k8sApi.Service
	exists     bool
	kubelego   kubelego.KubeLego
}

func New(client kubelego.KubeLego, namespace string, name string) *Service {
	service := &Service{
		exists:   true,
		kubelego: client,
	}

	var err error
	service.ServiceApi, err = client.KubeClient().Services(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			service.ServiceApi = &k8sApi.Service{
				ObjectMeta: k8sApi.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
			}
			service.exists = false

		} else {
			client.Log().Warn("Error during getting service: ", err)
		}
	}

	return service
}

func (s *Service) client() k8sClient.ServiceInterface {
	return s.kubelego.KubeClient().Services(s.ServiceApi.Namespace)
}

func (s *Service) Delete() error {

	if s.ServiceApi == nil || !s.exists {
		return nil
	}

	val, ok := s.ServiceApi.Annotations[kubelego.AnnotationKubeLegoManaged]
	if !ok || val != "true" {
		return fmt.Errorf(
			"do not delete service '%s/%s' as it has no %s annotiation",
			s.ServiceApi.Namespace,
			s.ServiceApi.Name,
			kubelego.AnnotationKubeLegoManaged,
		)
	}

	err := s.client().Delete(s.ServiceApi.Name)
	if err != nil {
		return err
	}

	s.ServiceApi = nil

	return nil
}

func (s *Service) Save() error {
	var obj *k8sApi.Service
	var err error

	if s.exists {
		obj, err = s.client().Update(s.ServiceApi)
	} else {
		obj, err = s.client().Create(s.ServiceApi)
		s.exists = true
	}
	if err != nil {
		return nil
	}

	s.ServiceApi = obj
	// Implement me
	return nil
}

func (s *Service) SetKubeLegoSpec() {
	port := s.kubelego.LegoHTTPPort()

	svc := s.ServiceApi
	svc.Annotations = map[string]string{
		kubelego.AnnotationKubeLegoManaged: "true",
	}

	svc.Spec.Selector = map[string]string{
		"app": "kube-lego",
	}

	if len(svc.Spec.Ports) != 1 ||
		svc.Spec.Ports[0].Port != int32(port.IntValue()) ||
		svc.Spec.Ports[0].TargetPort.IntValue() != int(port.IntValue()) {
		svc.Spec.Ports = []k8sApi.ServicePort{
			k8sApi.ServicePort{
				Port:       int32(port.IntValue()),
				TargetPort: port,
				Protocol:   "TCP",
			},
		}
	}

	svc.Spec.Type = "ClusterIP"
}

func (s *Service) SetEndpoints(endpointsList []string) (err error) {
	namespace := s.ServiceApi.Namespace
	client := s.kubelego.KubeClient().Endpoints(s.ServiceApi.Namespace)
	name := s.ServiceApi.Name

	exists := true
	endpoints, err := client.Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			endpoints = &k8sApi.Endpoints{
				ObjectMeta: k8sApi.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
			}
			exists = false
		} else {
			return err
		}
	}

	portIntStr := s.kubelego.LegoHTTPPort()
	port := portIntStr.IntValue()

	addr := make([]k8sApi.EndpointAddress, len(endpointsList))
	for i, endpoint := range endpointsList {
		addr[i] = k8sApi.EndpointAddress{
			IP: endpoint,
		}
	}

	endpoints.Subsets = []k8sApi.EndpointSubset{
		k8sApi.EndpointSubset{
			Addresses: addr,
			Ports: []k8sApi.EndpointPort{
				k8sApi.EndpointPort{
					Port:     int32(port),
					Protocol: "TCP",
				},
			},
		},
	}

	if exists {
		_, err = client.Update(endpoints)
	} else {
		_, err = client.Create(endpoints)
		exists = true
	}
	return
}

func (s *Service) Object() *k8sApi.Service {
	return s.ServiceApi
}
