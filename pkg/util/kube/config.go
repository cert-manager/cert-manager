package kube

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubeConfig will return a rest.Config for communicating with the Kubernetes API server.
// If apiServerHost is specified, a config without authentication that is configured
// to talk to the apiServerHost URL will be returned. Else, the in-cluster config will be loaded,
// and failing this, the config will be loaded from the users local kubeconfig directory
func KubeConfig(apiServerHost string) (*rest.Config, error) {
	var err error
	var cfg *rest.Config

	if len(apiServerHost) > 0 {
		cfg = new(rest.Config)
		cfg.Host = apiServerHost
	} else if cfg, err = rest.InClusterConfig(); err != nil {
		apiCfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()

		if err != nil {
			return nil, fmt.Errorf("error loading cluster config: %s", err.Error())
		}

		cfg, err = clientcmd.NewDefaultClientConfig(*apiCfg, &clientcmd.ConfigOverrides{}).ClientConfig()

		if err != nil {
			return nil, fmt.Errorf("error loading cluster client config: %s", err.Error())
		}
	}

	return cfg, nil
}
