/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package client

import (
	"fmt"
	"io/ioutil"
	"time"

	// This package is required to be imported to register all client
	// plugins.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

type Client struct {
	restConfig *rest.Config
	cmClient   cmclient.Interface
}

func New(kubeconfig string) (*Client, error) {
	restConfig, err := restConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	cmClient, err := cmclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return &Client{
		restConfig: restConfig,
		cmClient:   cmClient,
	}, nil
}

func (c *Client) CreateCertificateRequest(
	cr *cmapi.CertificateRequest) (*cmapi.CertificateRequest, error) {
	return c.cmClient.CertmanagerV1alpha2().CertificateRequests(cr.Namespace).Create(cr)
}

func (c *Client) CertificateRequest(ns, name string) (*cmapi.CertificateRequest, error) {
	return c.cmClient.CertmanagerV1alpha2().CertificateRequests(ns).Get(name, metav1.GetOptions{})
}

func (c *Client) UpdateCertificateRequest(cr *cmapi.CertificateRequest) (*cmapi.CertificateRequest, error) {
	return c.cmClient.CertmanagerV1alpha2().CertificateRequests(cr.Namespace).Update(cr)
}

func (c *Client) WaitForCertificateRequestReady(name, ns string, timeout time.Duration) (*cmapi.CertificateRequest, error) {
	var cr *cmapi.CertificateRequest
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {

			log.Debugf("polling CertificateRequest %s/%s for ready status", name, ns)

			var err error
			cr, err = c.cmClient.CertmanagerV1alpha2().CertificateRequests(ns).Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting CertificateRequest %s: %v", name, err)
			}

			reason := apiutil.CertificateRequestReadyReason(cr)
			switch reason {
			case cmapi.CertificateRequestReasonFailed:
				return false, fmt.Errorf("certificate request marked as failed: %s", reason)
			case cmapi.CertificateRequestReasonIssued:
				return true, nil
			default:
				return false, nil
			}
		},
	)

	if err != nil {
		return cr, err
	}

	return cr, nil
}

func restConfig(kubeconfig string) (*rest.Config, error) {
	if len(kubeconfig) == 0 {
		restConfig, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}

		return restConfig, nil
	}

	kubeconfigBytes, err := ioutil.ReadFile(kubeconfig)
	if err != nil {
		return nil, err
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfigBytes)
	if err != nil {
		return nil, err
	}

	return restConfig, nil
}
