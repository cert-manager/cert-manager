/*
Copyright 2017 The Kubernetes Authors.

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

package main

import (
	"flag"
	"fmt"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	_ "github.com/jetstack/cert-manager/pkg/apis/certmanager/install"
	"github.com/jetstack/cert-manager/pkg/client"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificates"
	"github.com/jetstack/cert-manager/pkg/controller/issuers"
	"github.com/jetstack/cert-manager/pkg/informers/externalversions"
	logpkg "github.com/jetstack/cert-manager/pkg/log"
)

var (
	apiServerHost = flag.String("apiserver", "", "optional API server host address")
	namespace     = flag.String("namespace", "", "optional namespace to operate within")
)

func main() {
	flag.Parse()
	log := logpkg.Default()

	cfg, err := kubeConfig(*apiServerHost)

	if err != nil {
		log.Fatalf("error getting in-cluster config: %s", err.Error())
	}

	cl, err := kubernetes.NewForConfig(cfg)

	if err != nil {
		log.Fatalf("error creating kubernetes clientset: %s", err.Error())
	}

	factory := informers.NewSharedInformerFactory(cl, time.Second*30)

	cmCl, err := client.NewForConfig(cfg)

	if err != nil {
		log.Fatalf("error creating cert-manager clientset: %s", err.Error())
	}

	cmFactory := externalversions.NewSharedInformerFactory(cmCl, time.Second*30)

	ctx := controller.Context{
		Client:                     cl,
		CertManagerClient:          cmCl,
		InformerFactory:            factory,
		CertManagerInformerFactory: cmFactory,
		Namespace:                  *namespace,
		Logger:                     log,
	}

	issuerCtrl := issuers.New(ctx)
	certificatesCtrl := certificates.New(ctx)

	stopCh := make(chan struct{})
	factory.Start(stopCh)
	cmFactory.Start(stopCh)

	go issuerCtrl.Run(5, stopCh)
	go certificatesCtrl.Run(5, stopCh)

	<-stopCh
}

// kubeConfig will return a rest.Config for communicating with the Kubernetes API server.
// If apiServerHost is specified, a config without authentication that is configured
// to talk to the apiServerHost URL will be returned. Else, the in-cluster config will be loaded,
// and failing this, the config will be loaded from the users local kubeconfig directory
func kubeConfig(apiServerHost string) (*rest.Config, error) {
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
