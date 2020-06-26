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

package certificaterequest

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	restclient "k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/ctl"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

var (
	long = templates.LongDesc(i18n.T(`
Create a new CertificateRequest resource based on a Certificate resource, by generating a private key locally and create a 'certificate signing request' to be submitted to a cert-manager Issuer.`))

	example = templates.Examples(i18n.T(`
# Create a CertificateRequest with the name 'my-cr', saving the private key in a file named 'my-cr.key'.
kubectl cert-manager create certificaterequest my-cr --from-certificate-file my-certificate.yaml

# Create a CertificateRequest in namespace default, provided no conflict with namespace defined in file.
kubectl cert-manager create certificaterequest my-cr --namespace default --from-certificate-file my-certificate.yaml

# Create a CertificateRequest and store private key in file 'new.key'.
kubectl cert-manager create certificaterequest my-cr --from-certificate-file my-certificate.yaml --output-key-file new.key
`))
)

var (
	// Dedicated scheme used by the ctl tool that has the internal cert-manager types,
	// and their conversion functions registered
	scheme = ctl.Scheme
)

// Options is a struct to support create certificaterequest command
type Options struct {
	CMClient   cmclient.Interface
	RESTConfig *restclient.Config
	// Namespace resulting from the merged result of all overrides
	// since namespace can be specified in file, as flag and in kube config
	CmdNamespace string
	// boolean indicating if there was an Override in determining CmdNamespace
	EnforceNamespace bool
	// Name of file that the generated private key will be written to
	// If not specified, the private key will be written to <NameOfCR>.key
	KeyFilename string
	// Path to a file containing a Certificate resource used as a template
	// when generating the CertificateRequest resource
	// Required
	InputFilename string

	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdCreateCR returns a cobra command for create CertificateRequest
func NewCmdCreateCR(ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "certificaterequest",
		Aliases: []string{"cr"},
		Short:   "Create a cert-manager CertificateRequest resource, using a Certificate resource as a template",
		Long:    long,
		Example: example,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Complete(factory))
			cmdutil.CheckErr(o.Run(args))
		},
	}
	cmd.Flags().StringVar(&o.InputFilename, "from-certificate-file", o.InputFilename,
		"Path to a file containing a Certificate resource used as a template when generating the CertificateRequest resource")
	cmd.Flags().StringVar(&o.KeyFilename, "output-key-file", o.KeyFilename,
		"Name of file that the generated private key will be written to")

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(args []string) error {
	if len(args) < 1 {
		return errors.New("the name of the CertificateRequest to be created has to be provided as argument")
	}
	if len(args) > 1 {
		return errors.New("only one argument can be passed in: the name of the CertificateRequest")
	}

	if o.KeyFilename != "" && (len(o.KeyFilename) < 4 || o.KeyFilename[len(o.KeyFilename)-4:] != ".key") {
		return errors.New("file to store private key must end in '.key'")
	}

	return nil
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete(f cmdutil.Factory) error {
	var err error

	o.CmdNamespace, o.EnforceNamespace, err = f.ToRawKubeConfigLoader().Namespace()
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

	// Read file as internal API version
	r := builder.
		WithScheme(scheme, schema.GroupVersion{Group: cmapiv1alpha2.SchemeGroupVersion.Group, Version: runtime.APIVersionInternal}).
		LocalParam(true).ContinueOnError().
		NamespaceParam(o.CmdNamespace).DefaultNamespace().
		FilenameParam(o.EnforceNamespace, &resource.FilenameOptions{Filenames: []string{o.InputFilename}}).Flatten().Do()

	if err := r.Err(); err != nil {
		return fmt.Errorf("error when getting Result from Builder: %s", err)
	}

	singleItemImplied := false
	infos, err := r.IntoSingleItemImplied(&singleItemImplied).Infos()
	if err != nil {
		return fmt.Errorf("error when getting infos out of Result: %s", err)
	}

	// Ensure only one object per command
	if len(infos) == 0 {
		return fmt.Errorf("no objects found in manifest file %q. Expected one Certificate object", o.InputFilename)
	}
	if len(infos) > 1 {
		return fmt.Errorf("multiple objects found in manifest file %q. Expected only one Certificate object", o.InputFilename)
	}
	info := infos[0]
	// Convert to v1alpha2 because that version is needed for functions that follow
	crtObj, err := scheme.ConvertToVersion(info.Object, cmapiv1alpha2.SchemeGroupVersion)
	if err != nil {
		return fmt.Errorf("failed to convert object into version v1alpha2: %v", err)
	}

	// Cast Object into Certificate
	crt, ok := crtObj.(*cmapiv1alpha2.Certificate)
	if !ok {
		return errors.New("decoded object is not a v1alpha2 Certificate")
	}

	signer, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return fmt.Errorf("error when generating new private key for CertificateRequest: %v", err)
	}

	keyData, err := pki.EncodePrivateKey(signer, crt.Spec.KeyEncoding)
	if err != nil {
		return fmt.Errorf("failed to encode new private key for CertificateRequest: %v", err)
	}

	crName := args[0]

	// Storing private key to file
	keyFileName := crName + ".key"
	if o.KeyFilename != "" {
		keyFileName = o.KeyFilename
	}
	if err := ioutil.WriteFile(keyFileName, keyData, 0600); err != nil {
		return fmt.Errorf("error when writing private key to file: %v", err)
	}
	fmt.Fprintf(o.Out, "Private key written to file %s\n", keyFileName)

	// Build CertificateRequest with name as specified by argument
	req, err := buildCertificateRequest(crt, keyData, crName)
	if err != nil {
		return fmt.Errorf("error when building CertificateRequest: %v", err)
	}

	ns := crt.Namespace
	if ns == "" {
		ns = o.CmdNamespace
	}
	req, err = o.CMClient.CertmanagerV1alpha2().CertificateRequests(ns).Create(context.TODO(), req, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating CertificateRequest: %v", err)
	}
	fmt.Fprintf(o.Out, "CertificateRequest %s has been created in namespace %s\n", req.Name, req.Namespace)

	return nil
}

// Builds a CertificateRequest
func buildCertificateRequest(crt *cmapiv1alpha2.Certificate, pk []byte, crName string) (*cmapiv1alpha2.CertificateRequest, error) {
	csrPEM, err := generateCSR(crt, pk)
	if err != nil {
		return nil, err
	}

	cr := &cmapiv1alpha2.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        crName,
			Annotations: crt.Annotations,
			Labels:      crt.Labels,
		},
		Spec: cmapiv1alpha2.CertificateRequestSpec{
			CSRPEM:    csrPEM,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
			Usages:    crt.Spec.Usages,
		},
	}

	return cr, nil
}

func generateCSR(crt *cmapiv1alpha2.Certificate, pk []byte) ([]byte, error) {
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
