/*
Copyright The cert-manager Authors.

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
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"os"
)

func BuildClientConfig(APIServerHost string, Kubeconfig string) (*rest.Config, error) {
	if APIServerHost == "" && Kubeconfig == "" {
		return rest.InClusterConfig()
	} else {
		return clientcmd.BuildConfigFromKubeconfigGetter(APIServerHost, getKubeConfigGetter(Kubeconfig))
	}
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

		return cfg, err
	}
}
