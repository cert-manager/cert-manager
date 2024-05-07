/*
Copyright 2020 The cert-manager Authors.

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

// Package base implements a basis for plugins that need to use the Kubernetes
// API to build upon.
package base

import (
	"context"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/internal"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/config"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/util"
)

type Base struct {
	// details is stored here after a call to Setup() to save constructing the
	// client on additional invocations to this instance of Base's Config function
	// in the event a suite is run in serial
	details *Details
}

var _ internal.Addon = &Base{}

// Details return the details about the certmanager instance deployed
type Details struct {
	// Config is exposed here to make it easier for upstream consumers to access
	// the global configuration.
	Config *config.Config

	// KubeConfig is the loaded Kubernetes configuration for addons to use.
	KubeConfig *rest.Config

	// KubeClient is a configured Kubernetes clientset for addons to use.
	KubeClient kubernetes.Interface
}

func (d *Details) Helper() *helper.Helper {
	return &helper.Helper{
		KubeClient: d.KubeClient,
	}
}

func (b *Base) Setup(c *config.Config, _ ...internal.AddonTransferableData) (internal.AddonTransferableData, error) {
	kubeConfig, err := util.LoadConfig(c.KubeConfig, c.KubeContext)
	if err != nil {
		return nil, err
	}

	kubeConfig.Burst = 9000
	kubeConfig.QPS = 9000

	kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	b.details = &Details{
		Config: c,

		KubeConfig: kubeConfig,
		KubeClient: kubeClientset,
	}

	return nil, nil
}

func (b *Base) Provision(_ context.Context) error {
	return nil
}

func (b *Base) Deprovision(_ context.Context) error {
	return nil
}

func (b *Base) Details() *Details {
	return b.details
}

func (b *Base) SupportsGlobal() bool {
	return true
}
