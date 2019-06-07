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

package webhook

import (
	"encoding/json"
	"errors"
	"fmt"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
)

type Webhook struct {
	restConfigShallowCopy rest.Config
}

func (r *Webhook) Name() string {
	return "webhook"
}

// Present creates a TXT record using the specified parameters
func (r *Webhook) Present(ch *v1alpha1.ChallengeRequest) error {
	cl, pl, solverName, err := r.buildPayload(ch, v1alpha1.ChallengeActionPresent)
	if err != nil {
		return err
	}

	result := cl.Post().Resource(solverName).Body(pl).Do()
	// we will check this error after parsing the response
	resErr := result.Error()

	// TODO: handle metav1.Status response type and print better error messages
	var respPayload v1alpha1.ChallengePayload
	if err := result.Into(&respPayload); err != nil {
		return utilerrors.NewAggregate([]error{resErr, err})
	}

	if respPayload.Response.Success && resErr == nil {
		klog.Infof("Present call succeeded")
		return nil
	}

	if respPayload.Response.Result == nil {
		return utilerrors.NewAggregate([]error{
			resErr,
			fmt.Errorf("invalid payload response, did not succeed but no result provided"),
		})
	}

	if respPayload.Response.Result.Message != "" {
		return errors.New(respPayload.Response.Result.Message)
	}

	return resErr
}

// CleanUp removes the TXT record matching the specified parameters
func (r *Webhook) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cl, pl, solverName, err := r.buildPayload(ch, v1alpha1.ChallengeActionCleanUp)
	if err != nil {
		return err
	}

	result := cl.Post().Resource(solverName).Body(pl).Do()
	// we will check this error after parsing the response
	resErr := result.Error()

	// TODO: handle metav1.Status response type and print better error messages
	var respPayload v1alpha1.ChallengePayload
	if err := result.Into(&respPayload); err != nil {
		return utilerrors.NewAggregate([]error{resErr, err})
	}

	if respPayload.Response.Success && resErr == nil {
		klog.Infof("CleanUp call succeeded")
		return nil
	}

	if respPayload.Response.Result == nil {
		return utilerrors.NewAggregate([]error{
			resErr,
			fmt.Errorf("invalid payload response, did not succeed but no result provided"),
		})
	}

	if respPayload.Response.Result.Message != "" {
		return errors.New(respPayload.Response.Result.Message)
	}

	return resErr
}

func (r *Webhook) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cfgShallowCopy := *kubeClientConfig
	cfgShallowCopy.APIPath = "/apis"
	cfgShallowCopy.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: scheme.Codecs}
	// We defer setting the GroupVersion of the rest client config to the
	// restClientForGroup function.

	if cfgShallowCopy.UserAgent == "" {
		cfgShallowCopy.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	r.restConfigShallowCopy = cfgShallowCopy

	return nil
}

func (r *Webhook) buildPayload(ch *v1alpha1.ChallengeRequest, action v1alpha1.ChallengeAction) (*rest.RESTClient, *v1alpha1.ChallengePayload, string, error) {
	// create a copy just to be certain we don't modify something unexpectedly
	req := ch.DeepCopy()

	// extract the complete solver config, including groupName and solverName
	cfg, err := loadConfig(*req.Config)
	if err != nil {
		return nil, nil, "", err
	}

	// obtain a REST client that can be used to communicate with the webhook
	cl, err := r.restClientForGroup(cfg.GroupName)
	if err != nil {
		return nil, nil, "", err
	}

	// build the ChallengePayload resource
	pl := &v1alpha1.ChallengePayload{
		Request: req,
	}
	pl.Request.Action = action
	// When using the webhook provider, the 'config' on the ChallengeRequest
	// will be the complete marshaled configuration as specified on the issuer.
	// Instead of passing all this extra config along, we instead extract out
	// only the 'config' field and submit that to the webhook.
	pl.Request.Config = cfg.Config

	return cl, pl, cfg.SolverName, nil
}

func loadConfig(cfgJSON apiext.JSON) (*cmapi.ACMEIssuerDNS01ProviderWebhook, error) {
	cfg := cmapi.ACMEIssuerDNS01ProviderWebhook{}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return nil, fmt.Errorf("error decoding solver config: %v", err)
	}

	return &cfg, nil
}

func (r *Webhook) restClientForGroup(g string) (*rest.RESTClient, error) {
	cfg := r.restConfigShallowCopy
	cfg.GroupVersion = &schema.GroupVersion{
		Group:   g,
		Version: v1alpha1.SchemeGroupVersion.Version,
	}

	return rest.RESTClientFor(&cfg)
}
