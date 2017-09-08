package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	intclient "github.com/jetstack-experimental/cert-manager/pkg/client"
	"github.com/jetstack-experimental/cert-manager/pkg/controller"
	_ "github.com/jetstack-experimental/cert-manager/pkg/controller/issuers"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	_ "github.com/jetstack-experimental/cert-manager/pkg/issuer/acme"
	"github.com/jetstack-experimental/cert-manager/pkg/kube"
)

type CertManagerControllerOptions struct {
	ControllerOptions *ControllerOptions

	StdOut io.Writer
	StdErr io.Writer
}

func NewCertManagerControllerOptions(out, errOut io.Writer) *CertManagerControllerOptions {
	o := &CertManagerControllerOptions{
		ControllerOptions: &ControllerOptions{},

		StdOut: out,
		StdErr: errOut,
	}

	return o
}

// NewCommandStartCertManagerController is a CLI handler for starting cert-manager
func NewCommandStartCertManagerController(out, errOut io.Writer, stopCh <-chan struct{}) *cobra.Command {
	o := NewCertManagerControllerOptions(out, errOut)

	cmd := &cobra.Command{
		Use:   "cert-manager-controller",
		Short: "Automated TLS controller for Kubernetes",
		Long: `
cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.`,

		// TODO: Refactor this function from this package
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			if err := o.RunCertManagerController(stopCh); err != nil {
				return err
			}
			return nil
		},
	}

	flags := cmd.Flags()
	o.ControllerOptions.AddFlags(flags)

	return cmd
}

func (o CertManagerControllerOptions) Validate(args []string) error {
	errors := []error{}
	errors = append(errors, o.ControllerOptions.Validate())
	return utilerrors.NewAggregate(errors)
}

func (o *CertManagerControllerOptions) Complete() error {
	return nil
}

func (o CertManagerControllerOptions) Context() (*controller.Context, error) {
	// Load the users Kubernetes config
	cfg, err := KubeConfig(o.ControllerOptions.APIServerHost)

	if err != nil {
		return nil, fmt.Errorf("error creating rest config: %s", err.Error())
	}

	// Create a Navigator api client
	intcl, err := intclient.NewForConfig(cfg)

	if err != nil {
		return nil, fmt.Errorf("error creating internal group client: %s", err.Error())
	}

	// Create a Kubernetes api client
	cl, err := kubernetes.NewForConfig(cfg)

	if err != nil {
		return nil, fmt.Errorf("error creating kubernetes client: %s", err.Error())
	}

	sharedInformerFactory := kube.NewSharedInformerFactory()

	issuerCtx := &issuer.Context{
		Client:                cl,
		CMClient:              intcl,
		SharedInformerFactory: sharedInformerFactory,
		Namespace:             o.ControllerOptions.Namespace,
	}

	// Create a context for controllers to use
	ctx := &controller.Context{
		Client:                cl,
		CMClient:              intcl,
		SharedInformerFactory: sharedInformerFactory,
		IssuerFactory:         issuer.NewFactory(issuerCtx),
		Namespace:             o.ControllerOptions.Namespace,
	}

	return ctx, nil
}

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

func (o CertManagerControllerOptions) RunCertManagerController(stopCh <-chan struct{}) error {
	ctx, err := o.Context()
	if err != nil {
		return err
	}
	// Start all known controller loops
	return controller.Start(ctx, controller.Known(), stopCh)
}
