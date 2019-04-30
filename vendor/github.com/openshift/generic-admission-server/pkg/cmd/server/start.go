package server

import (
	"fmt"
	"io"
	"net"

	"github.com/spf13/cobra"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	"github.com/openshift/generic-admission-server/pkg/apiserver"
)

const defaultEtcdPathPrefix = "/registry/online.openshift.io"

type AdmissionServerOptions struct {
	RecommendedOptions *genericoptions.RecommendedOptions

	AdmissionHooks []apiserver.AdmissionHook

	StdOut io.Writer
	StdErr io.Writer
}

func NewAdmissionServerOptions(out, errOut io.Writer, admissionHooks ...apiserver.AdmissionHook) *AdmissionServerOptions {
	o := &AdmissionServerOptions{
		// TODO we will nil out the etcd storage options.  This requires a later level of k8s.io/apiserver
		RecommendedOptions: genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			apiserver.Codecs.LegacyCodec(admissionv1beta1.SchemeGroupVersion),
			nil,
		),

		AdmissionHooks: admissionHooks,

		StdOut: out,
		StdErr: errOut,
	}
	o.RecommendedOptions.Etcd = nil
	o.RecommendedOptions.Admission = nil

	return o
}

// NewCommandStartMaster provides a CLI handler for 'start master' command
func NewCommandStartAdmissionServer(out, errOut io.Writer, stopCh <-chan struct{}, admissionHooks ...apiserver.AdmissionHook) *cobra.Command {
	o := NewAdmissionServerOptions(out, errOut, admissionHooks...)

	cmd := &cobra.Command{
		Short: "Launch a namespace reservation API server",
		Long:  "Launch a namespace reservation API server",
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			if err := o.RunAdmissionServer(stopCh); err != nil {
				return err
			}
			return nil
		},
	}

	flags := cmd.Flags()
	o.RecommendedOptions.AddFlags(flags)

	return cmd
}

func (o AdmissionServerOptions) Validate(args []string) error {
	return nil
}

func (o *AdmissionServerOptions) Complete() error {
	return nil
}

func (o AdmissionServerOptions) Config() (*apiserver.Config, error) {
	// TODO have a "real" external address
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	if err := o.RecommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	config := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			AdmissionHooks: o.AdmissionHooks,
		},
	}
	return config, nil
}

func (o AdmissionServerOptions) RunAdmissionServer(stopCh <-chan struct{}) error {
	config, err := o.Config()
	if err != nil {
		return err
	}

	server, err := config.Complete().New()
	if err != nil {
		return err
	}
	return server.GenericAPIServer.PrepareRun().Run(stopCh)
}
