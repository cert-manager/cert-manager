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
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/pkg/webhook"
)

var (
	long = templates.LongDesc(i18n.T(`
Create a cert-manager CertificateRequest resource and store private key on local file.`))

	example = templates.Examples(i18n.T(`
# Create a CertificateRequest from from file.
kubectl cert-manager create certificaterequest -f my-certificate.yaml

# Create a CertificateRequest in namespace default, provided no conflict with namespace defined in file.
kubectl cert-manager create certificaterequest --namespace default -f my-certificate.yaml

# Create a CertificateRequest with the name 'my-cr', private key will be stored in file 'my-cr.key'.
kubectl cert-manager create certificaterequest my-cr -f my-certificate.yaml

# Create a CertificateRequest and store private key in file 'new.key'.
kubectl cert-manager create certificaterequest my-cr -f my-certificate.yaml --output-key-file new.key
`))
)

var (
	// Use the webhook's scheme as it already has the internal cert-manager types,
	// and their conversion functions registered.
	// In future we may we want to consider creating a dedicated scheme used by
	// the ctl tool.
	scheme = webhook.Scheme
)

// Options is a struct to support create certificaterequest command
type Options struct {
	CMClient         cmclient.Interface
	RESTConfig       *restclient.Config
	CmdNamespace     string
	EnforceNamespace bool
	KeyFilename      string

	resource.FilenameOptions
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
		Short:   "Create a cert-manager CertificateRequest resource",
		Long:    long,
		Example: example,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return errors.New("only one argument can be passed in: the name of the CertificateRequest")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(factory))
			cmdutil.CheckErr(o.Run(args))
		},
	}

	cmdutil.AddFilenameOptionFlags(cmd, &o.FilenameOptions, "Path to the manifest of a Certificate resource")
	cmd.Flags().StringVar(&o.KeyFilename, "output-key-file", o.KeyFilename,
		"Name of the file the private key is to be stored in")

	return cmd
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete(f cmdutil.Factory) error {
	var err error

	err = o.FilenameOptions.RequireFilenameOrKustomize()
	if err != nil {
		return err
	}

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
		FilenameParam(o.EnforceNamespace, &o.FilenameOptions).Flatten().Do()

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
		return errors.New("no object passed to create certificaterequest")
	}
	if len(infos) > 1 {
		objects := ""
		for _, info := range infos {
			namespace := info.Namespace
			if namespace == "" {
				namespace = "default"
			}
			objects = objects + fmt.Sprintf("Object with kind %s, name %s, namespace %s\n",
				info.Object.GetObjectKind().GroupVersionKind().Kind,
				info.Name,
				namespace)
		}
		return fmt.Errorf("multiple objects passed to create certificaterequest:\n%s", objects)
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

	// Use name for CertificateRequest if specified as arg, else will use name of the Certificate as GenerateName
	crName := ""
	if len(args) > 0 {
		crName = args[0]
	}
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
		return fmt.Errorf("error when creating CertificateRequest through client: %v", err)
	}
	fmt.Fprintf(o.Out, "CertificateRequest %s has been created in namespace %s\n", req.Name, req.Namespace)

	// Storing private key to file
	keyFileName := req.Name + ".key"
	if o.KeyFilename != "" {
		keyFileName = o.KeyFilename
	}
	if err := ioutil.WriteFile(keyFileName, keyData, 0644); err != nil {
		return fmt.Errorf("error when writing private key to file: %v", err)
	}

	fmt.Fprintf(o.Out, "Private key written to file %s\n", keyFileName)

	return nil
}

// Builds a CertificateRequest
func buildCertificateRequest(crt *cmapiv1alpha2.Certificate, pk []byte, crName string) (*cmapiv1alpha2.CertificateRequest, error) {
	csrPEM, err := generateCSR(crt, pk)
	if err != nil {
		return nil, err
	}

	annotations := make(map[string]string, len(crt.Annotations)+2)
	for k, v := range crt.Annotations {
		annotations[k] = v
	}
	annotations[cmapiv1alpha2.CRPrivateKeyAnnotationKey] = crt.Spec.SecretName
	annotations[cmapiv1alpha2.CertificateNameKey] = crt.Name

	cr := &cmapiv1alpha2.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: annotations,
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
	if crName != "" {
		cr.Name = crName
	} else {
		cr.GenerateName = crt.Name + "-"
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
