/*
Copyright 2021 The cert-manager Authors.

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

package kube

import (
	"fmt"
	"os"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func BuildClientConfig(apiServerHost string, kubeConfig string) (*rest.Config, error) {
	if apiServerHost == "" && kubeConfig == "" {
		return rest.InClusterConfig()
	}
	return clientcmd.BuildConfigFromKubeconfigGetter(apiServerHost, getKubeConfigGetter(kubeConfig))
}

func getKubeConfigGetter(kubeConfig string) clientcmd.KubeconfigGetter {
	return func() (*clientcmdapi.Config, error) {
		if len(kubeConfig) == 0 {
			return clientcmdapi.NewConfig(), nil
		}
		cfg, err := clientcmd.LoadFromFile(kubeConfig)
		if os.IsNotExist(err) {
			return clientcmdapi.NewConfig(), err
		}

		if err != nil {
			return clientcmdapi.NewConfig(), fmt.Errorf("error loading config file \"%s\": %v", kubeConfig, err)
		}

		return cfg, nil
	}
}
