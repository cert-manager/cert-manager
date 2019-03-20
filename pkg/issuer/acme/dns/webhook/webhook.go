package webhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

type Webhook struct {
	restConfigShallowCopy rest.Config
}

func (r *Webhook) Name() string {
	return "webhook"
}

// Present creates a TXT record using the specified parameters
func (r *Webhook) Present(ch *v1alpha1.ChallengeRequest) error {
	pl := &v1alpha1.ChallengePayload{
		Request: ch,
	}
	pl.Request.Action = v1alpha1.ChallengeActionPresent

	cfg, err := r.loadConfig(*ch.Config)
	if err != nil {
		return err
	}

	cl, err := r.restClientForGroup(cfg.GroupName)
	if err != nil {
		return err
	}

	result := cl.Post().Resource(cfg.SolverName).Body(&pl).Do()
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
	pl := &v1alpha1.ChallengePayload{
		Request: ch,
	}
	pl.Request.Action = v1alpha1.ChallengeActionCleanUp

	cfg, err := r.loadConfig(*ch.Config)
	if err != nil {
		return err
	}

	cl, err := r.restClientForGroup(cfg.GroupName)
	if err != nil {
		return err
	}

	result := cl.Post().Resource(cfg.SolverName).Body(&pl).Do()
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

func (r *Webhook) loadConfig(cfgJSON apiext.JSON) (*v1alpha1.ACMEIssuerDNS01ProviderWebhook, error) {
	cfg := v1alpha1.ACMEIssuerDNS01ProviderWebhook{}
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
