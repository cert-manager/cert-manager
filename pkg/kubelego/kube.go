package kubelego

import (
	"errors"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	certmanager "github.com/munnerz/cert-manager/pkg/client/clientset_generated/clientset"
)

func (kl *KubeLego) InitKube() error {

	// Try in cluster client first
	config, err := kl.kubeConfig()

	if err != nil {
		return err
	}

	kl.Log().Info("connecting to kubernetes api: ", config.Host)
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	kl.Log().Info("connecting to kubernetes tpr api")
	tprKubeClient, err := certmanager.NewForConfig(config)
	if err != nil {
		return err
	}

	version, err := kubeClient.ServerVersion()
	if err != nil {
		return err
	}
	kl.Log().Infof("successfully connected to kubernetes api %s", version.String())

	kl.kubeClient = kubeClient
	kl.tprKubeClient = tprKubeClient
	return nil
}

func (kl *KubeLego) kubeConfig() (*rest.Config, error) {
	// Try in cluster client first
	config, err := rest.InClusterConfig()
	if err != nil {
		kl.Log().Warnf("failed to create in-cluster client: %v.", err)

		// fall back to kubeconfig
		// TODO: Link to kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", "kubeconfig")
		if err != nil {
			kl.Log().Warnf("failed to create kubeconfig client: %v.", err)
			return nil, errors.New("kube init failed as both in-cluster and dev connection unavailable")
		}
	}
	return config, nil
}

func (kl *KubeLego) Namespace() string {
	return kl.legoNamespace
}
