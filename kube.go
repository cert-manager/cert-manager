package main

import (
	"errors"
	"log"
	"reflect"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/util"
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

func (kl *KubeLego) WatchConfig() {

	oldList := &extensions.IngressList{}

	rateLimiter := util.NewTokenBucketRateLimiter(0.1, 1)

	ingClient := kl.KubeClient.Extensions().Ingress(api.NamespaceAll)

	for {
		rateLimiter.Accept()

		list, err := ingClient.List(api.ListOptions{})
		if err != nil {
			log.Printf("Error while retrieving ingress list: ", err)
			continue
		}

		if reflect.DeepEqual(oldList, list) {
			continue
		}
		oldList = list

		kl.ProcessIngress(list)

	}

}

func (kl *KubeLego) ProcessIngress(list *extensions.IngressList) error {
	log.Printf("Processing ingress list")
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
