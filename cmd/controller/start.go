package main

import (
	"fmt"
	"io"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/jetstack/cert-manager/cmd/controller/app"
	"github.com/jetstack/cert-manager/cmd/controller/app/options"
	_ "github.com/jetstack/cert-manager/pkg/controller/certificates"
	_ "github.com/jetstack/cert-manager/pkg/controller/clusterissuers"
	_ "github.com/jetstack/cert-manager/pkg/controller/ingress-shim"
	_ "github.com/jetstack/cert-manager/pkg/controller/issuers"
	_ "github.com/jetstack/cert-manager/pkg/issuer/acme"
	_ "github.com/jetstack/cert-manager/pkg/issuer/ca"
	_ "github.com/jetstack/cert-manager/pkg/issuer/vault"
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
				glog.Fatalf("error validating options: %s", err.Error())
			}
			go StartPrometheusMetricsServer(stopCh)
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
