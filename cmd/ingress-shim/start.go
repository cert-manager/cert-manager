package main

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/jetstack/cert-manager/cmd/ingress-shim/options"
	"github.com/jetstack/cert-manager/pkg/util"
)

// NewCommandStartController is a CLI handler for starting ingress-shim-controller
func NewCommandStartController(stopCh <-chan struct{}) *cobra.Command {
	o := options.NewControllerOptions()

	cmd := &cobra.Command{
		Use:   "ingress-shim-controller",
		Short: fmt.Sprintf("Automate creation of Certificate resources for Ingress (%s) (%s)", util.AppVersion, util.AppGitCommit),
		Long: `
This is a small binary that can be run alongside any cert-manager deployment
in order to automatically create Certificate resources for Ingresses when a
particular annotation is found on an ingress resource.

This allows users to consume certificates from cert-manager without having to
manually create Certificate resources`,

		// TODO: Refactor this function from this package
		Run: func(cmd *cobra.Command, args []string) {
			if err := o.Validate(); err != nil {
				glog.Fatalf("error validating options: %s", err.Error())
			}
			Run(o, stopCh)
		},
	}

	flags := cmd.Flags()
	o.AddFlags(flags)

	return cmd
}
