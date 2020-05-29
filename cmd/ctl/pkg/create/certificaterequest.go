/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package create

import (
	"context"
	"encoding/pem"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	restclient "k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

var (
	long = templates.LongDesc(i18n.T(`
Create a cert-manager CertificateRequest resource for one-time Certificate issuing without auto renewal.`))

	example = templates.Examples(i18n.T(`
`))

	alias = []string{"cr"}

	certificateGvk = cmapi.SchemeGroupVersion.WithKind("Certificate")
)

// Options is a struct to support create certificaterequest command
type Options struct {
	CMClient   cmclient.Interface
	RESTConfig *restclient.Config

	// The Namespace that the CertificateRequest to be created resides in.
	// This flag registration is handled by cmdutil.Factory
	Namespace string

	resource.FilenameOptions
	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdCreateCertficate returns a cobra command for create CertificateRequest
func NewCmdCreateCertficate(ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "certificaterequest",
		Aliases: alias,
		Short:   "Create a CertificateRequest resource",
		Long:    long,
		Example: example,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(factory))
			cmdutil.CheckErr(o.Run(args))
		},
	}

	cmdutil.AddFilenameOptionFlags(cmd, &o.FilenameOptions, "Path to a the manifest of Certificate resource.")

	return cmd
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete(f cmdutil.Factory) error {
	var err error

	err = o.FilenameOptions.RequireFilenameOrKustomize()
	if err != nil {
		return err
	}

	o.Namespace, _, err = f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	o.RESTConfig, err = f.ToRESTConfig()
	if err != nil {
		return err
	}

	o.CMClient, err = cmclient.NewForConfig(o.RESTConfig)
	if err != nil {
		return err
	}

	return nil
}

// Run executes create certificaterequest command
func (o *Options) Run(args []string) error {
	builder := new(resource.Builder)

	r := builder.Unstructured().LocalParam(true).ContinueOnError().
		FilenameParam(false, &o.FilenameOptions).Flatten().Do()

	if err := r.Err(); err != nil {
		return fmt.Errorf("error here: %s", err)
	}

	singleItemImplied := false
	infos, err := r.IntoSingleItemImplied(&singleItemImplied).Infos()
	if err != nil {
		return fmt.Errorf("error here instead: %s", err)
	}

	if len(infos) == 0 {
		return fmt.Errorf("no certificate passed to create certificaterequest")
	}

	for _, info := range infos {
		if info.Object.GetObjectKind().GroupVersionKind().Kind != "Certificate" {
			return fmt.Errorf("the manifest passed in should be for resource of kind Certificate")
		}

		fmt.Println(info.Object)

		//TODO: decode that info into Certificate
		crt := &cmapi.Certificate{}

		expectedReqName, err := apiutil.ComputeCertificateRequestName(crt)
		if err != nil {
			return fmt.Errorf("internal error hashing certificate spec: %v", err)
		}

		signer, err := pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			return fmt.Errorf("error when generating private key")
		}

		keyData, err := pki.EncodePrivateKey(signer, crt.Spec.KeyEncoding)
		if err != nil {
			return fmt.Errorf("error when encoding private key")
		}

		req, err := o.buildCertificateRequest(crt, expectedReqName, keyData)
		if err != nil {
			return err
		}

		req, err = o.CMClient.CertmanagerV1alpha2().CertificateRequests(crt.Namespace).Create(context.TODO(), req, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error when creating CertifcateRequest through client")
		}

	}

	return nil
}

func (o *Options) buildCertificateRequest(crt *cmapi.Certificate, name string, pk []byte) (*cmapi.CertificateRequest, error) {
	csrPEM, err := generateCSR(crt, pk)
	if err != nil {
		return nil, err
	}

	annotations := make(map[string]string, len(crt.Annotations)+2)
	for k, v := range crt.Annotations {
		annotations[k] = v
	}
	annotations[cmapi.CRPrivateKeyAnnotationKey] = crt.Spec.SecretName
	annotations[cmapi.CertificateNameKey] = crt.Name

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       crt.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
			Annotations:     annotations,
			Labels:          crt.Labels,
		},
		Spec: cmapi.CertificateRequestSpec{
			CSRPEM:    csrPEM,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
			Usages:    crt.Spec.Usages,
		},
	}

	return cr, nil
}

func generateCSR(crt *cmapi.Certificate, pk []byte) ([]byte, error) {
	csr, err := pki.GenerateCSR(crt)
	if err != nil {
		return nil, err
	}

	signer, err := pki.DecodePrivateKeyBytes(pk)
	if err != nil {
		return nil, err
	}

	csrDER, err := pki.EncodeCSR(csr, signer)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	})

	return csrPEM, nil
}
