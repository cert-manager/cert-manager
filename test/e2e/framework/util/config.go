package util

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func RestclientConfig(config, context string) (*clientcmdapi.Config, error) {
	if config == "" {
		return nil, fmt.Errorf("Config file must be specified to load client config")
	}
	c, err := clientcmd.LoadFromFile(config)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err.Error())
	}
	if context != "" {
		c.CurrentContext = context
	}
	return c, nil
}

func LoadConfig(config, context string) (*rest.Config, error) {
	c, err := RestclientConfig(config, context)
	if err != nil {
		return nil, err
	}
	return clientcmd.NewDefaultClientConfig(*c, &clientcmd.ConfigOverrides{}).ClientConfig()
}
