package webhook

import (
	"errors"
	"fmt"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
)

type Webhook struct {
	restConfigShallowCopy rest.Config
	issuer                v1alpha1.GenericIssuer
	resourceNamespace     string
	groupName             string
	solverName            string
	config                *apiext.JSON
}

func NewWebhook(issuer v1alpha1.GenericIssuer, resourceNamespace string, restConfig *rest.Config, groupName, solverName string, config *apiext.JSON) (*Webhook, error) {
	return &Webhook{
		restConfigShallowCopy: *restConfig,
		issuer:                issuer,
		resourceNamespace:     resourceNamespace,
		groupName:             groupName,
		solverName:            solverName,
		config:                config,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (r *Webhook) Present(ch *v1alpha1.Challenge, fqdn string) error {
	pl := r.buildPayload(ch, fqdn)
	pl.Request.Action = v1alpha1.ChallengeActionPresent

	cl, err := r.buildRESTClient()
	if err != nil {
		return err
	}

	result := cl.Post().Resource(r.solverName).Body(&pl).Do()
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
func (r *Webhook) CleanUp(ch *v1alpha1.Challenge, fqdn string) error {
	pl := r.buildPayload(ch, fqdn)
	pl.Request.Action = v1alpha1.ChallengeActionCleanUp

	cl, err := r.buildRESTClient()
	if err != nil {
		return err
	}

	result := cl.Post().Resource(r.solverName).Body(&pl).Do()
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

func (r *Webhook) buildRESTClient() (*rest.RESTClient, error) {
	r.restConfigShallowCopy.GroupVersion = &schema.GroupVersion{
		Group:   r.groupName,
		Version: v1alpha1.SchemeGroupVersion.Version,
	}
	r.restConfigShallowCopy.APIPath = "/apis"
	r.restConfigShallowCopy.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: scheme.Codecs}

	if r.restConfigShallowCopy.UserAgent == "" {
		r.restConfigShallowCopy.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	return rest.RESTClientFor(&r.restConfigShallowCopy)
}

func (r *Webhook) buildPayload(ch *v1alpha1.Challenge, fqdn string) v1alpha1.ChallengePayload {
	return v1alpha1.ChallengePayload{
		Request: &v1alpha1.ChallengeRequest{
			ResolvedFQDN:      fqdn,
			ResourceNamespace: r.resourceNamespace,
			Challenge:         *ch,
			Config:            r.config,
		},
	}
}
