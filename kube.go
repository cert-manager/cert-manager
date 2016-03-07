package main

import (
	"errors"
	"log"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	client "k8s.io/kubernetes/pkg/client/unversioned"
)

func (kl *KubeLego) InitKube() error {

	// Try in cluster client first
	kubeClient, err := client.NewInCluster()
	if err != nil {
		log.Printf("failed to create in-cluster client: %v.", err)

		// fall back to 127.0.0.1:8080 for dev
		kubeClient, err = client.New(
			&client.Config{
				Host: "127.0.0.1:8080",
			},
		)
		if err != nil {
			log.Printf("failed to create test cluster client: %v.", err)
			return errors.New("kube init failed as both in-cluster and dev connection unavailable")
		}
	}

	kl.KubeClient = kubeClient
	return nil
}

func (kl *KubeLego) GetSecret(name string, namespace string) (*api.Secret, error) {
	secretClient := kl.KubeClient.Secrets(namespace)
	return secretClient.Get(name)
}

func (kl *KubeLego) CreateSecret(namespace string, secret *api.Secret) (*api.Secret, error) {
	secretClient := kl.KubeClient.Secrets(namespace)
	return secretClient.Create(secret)
}

func (kl *KubeLego) UpdateSecret(namespace string, secret *api.Secret) (*api.Secret, error) {
	secretClient := kl.KubeClient.Secrets(namespace)
	return secretClient.Update(secret)
}

func (kl *KubeLego) Namespace() string {
	return api.NamespaceDefault
}

func (kl *KubeLego) ListIngress() (*extensions.IngressList, error) {
	ingClient := kl.KubeClient.Extensions().Ingress(api.NamespaceAll)
	return ingClient.List(api.ListOptions{})
}

func (kl *KubeLego) ProcessIngress() error {
	list, err := kl.ListIngress()
	if err != nil {
		return err
	}

	for _, ingress := range list.Items {
		ing := Ingress{
			Ingress:  ingress,
			KubeLego: kl,
		}
		if ing.Ignore() {
			log.Printf("ignoring %s as it has no annotations", ing.String())
			continue
		}
		ing.Process()
	}

	return nil
}
