package controller

import (
	"k8s.io/client-go/kubernetes"

	clientset "github.com/jetstack-experimental/cert-manager/pkg/client/clientset"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/kube"
)

type Context struct {
	Client   kubernetes.Interface
	CMClient clientset.Interface

	SharedInformerFactory kube.SharedInformerFactory
	IssuerFactory         issuer.Factory

	Namespace string
}
