package kubelego

import (
	"errors"
	"reflect"

	k8sMeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	k8sApi "k8s.io/client-go/pkg/api/v1"
	k8sExtensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
)

func (kl *KubeLego) InitKube() error {

	// Try in cluster client first
	config, err := rest.InClusterConfig()
	if err != nil {
		kl.Log().Warnf("failed to create in-cluster client: %v.", err)

		// fall back to kubeconfig
		// TODO: Link to kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", "kubeconfig")
		if err != nil {
			kl.Log().Warnf("failed to create kubeconfig client: %v.", err)
			return errors.New("kube init failed as both in-cluster and dev connection unavailable")
		}
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	version, err := kubeClient.ServerVersion()
	if err != nil {
		return err
	}
	kl.Log().Infof("connected to kubernetes api %s", version.String())

	kl.kubeClient = kubeClient
	return nil
}

func (kl *KubeLego) Namespace() string {
	return kl.legoNamespace
}

func (kl *KubeLego) WatchConfig() {

	oldList := &k8sExtensions.IngressList{}

	rateLimiter := flowcontrol.NewTokenBucketRateLimiter(0.1, 1)

	ingClient := kl.kubeClient.Ingresses(k8sApi.NamespaceAll)

	for {
		rateLimiter.Accept()

		list, err := ingClient.List(k8sMeta.ListOptions{})
		if err != nil {
			kl.Log().Warn("Error while retrieving ingress list: ", err)
			continue
		}

		if reflect.DeepEqual(oldList, list) {
			continue
		}
		oldList = list

		kl.Reconfigure()

	}

}
