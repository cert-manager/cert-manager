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

package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/cmd/controller/app"
	"github.com/jetstack/cert-manager/cmd/controller/app/options"
	_ "github.com/jetstack/cert-manager/pkg/controller/acmechallenges"
	_ "github.com/jetstack/cert-manager/pkg/controller/acmeorders"
	_ "github.com/jetstack/cert-manager/pkg/controller/certificates"
	_ "github.com/jetstack/cert-manager/pkg/controller/clusterissuers"
	_ "github.com/jetstack/cert-manager/pkg/controller/ingress-shim"
	_ "github.com/jetstack/cert-manager/pkg/controller/issuers"
	_ "github.com/jetstack/cert-manager/pkg/issuer/acme"
	_ "github.com/jetstack/cert-manager/pkg/issuer/ca"
	_ "github.com/jetstack/cert-manager/pkg/issuer/selfsigned"
	_ "github.com/jetstack/cert-manager/pkg/issuer/vault"
	_ "github.com/jetstack/cert-manager/pkg/issuer/venafi"
	"github.com/jetstack/cert-manager/pkg/util"
)

type CertManagerControllerOptions struct {
	ControllerOptions *options.ControllerOptions

	StdOut io.Writer
	StdErr io.Writer
}

func NewCertManagerControllerOptions(out, errOut io.Writer) *CertManagerControllerOptions {
	o := &CertManagerControllerOptions{
		ControllerOptions: options.NewControllerOptions(),

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
		Short: fmt.Sprintf("Automated TLS controller for Kubernetes (%s) (%s)", util.AppVersion, util.AppGitCommit),
		Long: `
cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.`,

		// TODO: Refactor this function from this package
		Run: func(cmd *cobra.Command, args []string) {
			if err := o.Validate(args); err != nil {
				klog.Fatalf("error validating options: %s", err.Error())
			}

			klog.Infof("starting cert-manager %s (revision %s)", util.AppVersion, util.AppGitCommit)
			o.RunCertManagerController(stopCh)
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

func (o CertManagerControllerOptions) RunCertManagerController(stopCh <-chan struct{}) {
	app.Run(o.ControllerOptions, stopCh)
}
