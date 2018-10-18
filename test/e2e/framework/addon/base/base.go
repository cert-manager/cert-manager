// Package base implements a basis for plugins that need to use the Kubernetes
// API to build upon.
package base

import (
	"k8s.io/client-go/kubernetes"

	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/util"
)

type Base struct {
	// details is stored here after a call to Setup() to save constructing the
	// client on additional invocations to this instance of Base's Config function
	// in the event a suite is run in serial
	details *Details
}

// Details return the details about the certmanager instance deployed
type Details struct {
	// Config is exposed here to make it easier for upstream consumers to access
	// the global configuration.
	Config *config.Config

	// KubeClient is a configured Kubernetes clientset for addons to use.
	KubeClient kubernetes.Interface
}

func (b *Base) Setup(c *config.Config) error {
	kubeConfig, err := util.LoadConfig(c.KubeConfig, c.KubeContext)
	if err != nil {
		return err
	}

	kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	b.details = &Details{
		Config:     c,
		KubeClient: kubeClientset,
	}

	return nil
}

func (b *Base) Provision() error {
	return nil
}

func (b *Base) Deprovision() error {
	return nil
}

func (b *Base) Details() *Details {
	return b.details
}

func (b *Base) SupportsGlobal() bool {
	return true
}
