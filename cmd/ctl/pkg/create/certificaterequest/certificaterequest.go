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

package certificaterequest

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/ctl"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var (
	long = templates.LongDesc(i18n.T(`
Create a new CertificateRequest resource based on a Certificate resource, by generating a private key locally and create a 'certificate signing request' to be submitted to a cert-manager Issuer.`))

	example = templates.Examples(i18n.T(build.WithTemplate(`
# Create a CertificateRequest with the name 'my-cr', saving the private key in a file named 'my-cr.key'.
{{.BuildName}} create certificaterequest my-cr --from-certificate-file my-certificate.yaml

# Create a CertificateRequest in namespace default, provided no conflict with namespace defined in file.
{{.BuildName}} create certificaterequest my-cr --namespace default --from-certificate-file my-certificate.yaml

# Create a CertificateRequest and store private key in file 'new.key'.
{{.BuildName}} create certificaterequest my-cr --from-certificate-file my-certificate.yaml --output-key-file new.key

# Create a CertificateRequest, wait for it to be signed for up to 5 minutes (default) and store the x509 certificate in file 'new.crt'.
{{.BuildName}} create certificaterequest my-cr --from-certificate-file my-certificate.yaml --fetch-certificate --output-cert-file new.crt

# Create a CertificateRequest, wait for it to be signed for up to 20 minutes and store the x509 certificate in file 'my-cr.crt'.
{{.BuildName}} create certificaterequest my-cr --from-certificate-file my-certificate.yaml --fetch-certificate --timeout 20m
`)))
)

var (
	// Dedicated scheme used by the ctl tool that has the internal cert-manager types,
	// and their conversion functions registered
	scheme = ctl.Scheme
)

// Options is a struct to support create certificaterequest command
type Options struct {
	// Name of file that the generated private key will be stored in
	// If not specified, the private key will be written to <NameOfCR>.key
	KeyFilename string
	// If true, will wait for CertificateRequest to be ready to store the x509 certificate in a file
	// Command will block until CertificateRequest is ready or timeout as specified by Timeout happens
	FetchCert bool
	// Name of file that the generated x509 certificate will be stored in if --fetch-certificate flag is set
	// If not specified, the private key will be written to <NameOfCR>.crt
	CertFileName string
	// Path to a file containing a Certificate resource used as a template
	// when generating the CertificateRequest resource
	// Required
	InputFilename string
	// Length of time the command blocks to wait on CertificateRequest to be ready if --fetch-certificate flag is set
	// If not specified, default value is 5 minutes
	Timeout time.Duration

	genericclioptions.IOStreams
	*factory.Factory
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdCreateCR returns a cobra command for create CertificateRequest
func NewCmdCreateCR(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:               "certificaterequest",
		Aliases:           []string{"cr"},
		Short:             "Create a cert-manager CertificateRequest resource, using a Certificate resource as a template",
		Long:              long,
		Example:           example,
		ValidArgsFunction: factory.ValidArgsListCertificateRequests(ctx, &o.Factory),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Run(ctx, args))
		},
	}
	cmd.Flags().StringVar(&o.InputFilename, "from-certificate-file", o.InputFilename,
		"Path to a file containing a Certificate resource used as a template when generating the CertificateRequest resource")
	cmd.Flags().StringVar(&o.KeyFilename, "output-key-file", o.KeyFilename,
		"Name of file that the generated private key will be written to")
	cmd.Flags().StringVar(&o.CertFileName, "output-certificate-file", o.CertFileName,
		"Name of the file the certificate is to be stored in")
	cmd.Flags().BoolVar(&o.FetchCert, "fetch-certificate", o.FetchCert,
		"If set to true, command will wait for CertificateRequest to be signed to store x509 certificate in a file")
	cmd.Flags().DurationVar(&o.Timeout, "timeout", 5*time.Minute,
		"Time before timeout when waiting for CertificateRequest to be signed, must include unit, e.g. 10m or 1h")

	o.Factory = factory.New(ctx, cmd)

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

	if o.InputFilename == "" {
		return errors.New("the path to a YAML manifest of a Certificate resource cannot be empty, please specify by using --from-certificate-file flag")
	}

	if o.KeyFilename != "" && o.CertFileName != "" && o.KeyFilename == o.CertFileName {
		return errors.New("the file to store private key cannot be the same as the file to store certificate")
	}

	if !o.FetchCert && o.CertFileName != "" {
		return errors.New("cannot specify file to store certificate if not waiting for and fetching certificate, please set --fetch-certificate flag")
	}

	return nil
}

// Run executes create certificaterequest command
func (o *Options) Run(ctx context.Context, args []string) error {
	builder := new(resource.Builder)

	// Read file as internal API version
	r := builder.
		WithScheme(scheme, schema.GroupVersion{Group: cmapi.SchemeGroupVersion.Group, Version: runtime.APIVersionInternal}).
		LocalParam(true).ContinueOnError().
		NamespaceParam(o.Namespace).DefaultNamespace().
		FilenameParam(o.EnforceNamespace, &resource.FilenameOptions{Filenames: []string{o.InputFilename}}).Flatten().Do()

	if err := r.Err(); err != nil {
		return err
	}

	singleItemImplied := false
	infos, err := r.IntoSingleItemImplied(&singleItemImplied).Infos()
	if err != nil {
		return err
	}

	// Ensure only one object per command
	if len(infos) == 0 {
		return fmt.Errorf("no objects found in manifest file %q. Expected one Certificate object", o.InputFilename)
	}
	if len(infos) > 1 {
		return fmt.Errorf("multiple objects found in manifest file %q. Expected only one Certificate object", o.InputFilename)
	}
	info := infos[0]
	// Convert to v1 because that version is needed for functions that follow
	crtObj, err := scheme.ConvertToVersion(info.Object, cmapi.SchemeGroupVersion)
	if err != nil {
		return fmt.Errorf("failed to convert object into version v1: %w", err)
	}

	// Cast Object into Certificate
	crt, ok := crtObj.(*cmapi.Certificate)
	if !ok {
		return errors.New("decoded object is not a v1 Certificate")
	}

	crt = crt.DeepCopy()
	if crt.Spec.PrivateKey == nil {
		crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}

	signer, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return fmt.Errorf("error when generating new private key for CertificateRequest: %w", err)
	}

	keyData, err := pki.EncodePrivateKey(signer, crt.Spec.PrivateKey.Encoding)
	if err != nil {
		return fmt.Errorf("failed to encode new private key for CertificateRequest: %w", err)
	}

	crName := args[0]

	// Storing private key to file
	keyFileName := crName + ".key"
	if o.KeyFilename != "" {
		keyFileName = o.KeyFilename
	}
	if err := os.WriteFile(keyFileName, keyData, 0600); err != nil {
		return fmt.Errorf("error when writing private key to file: %w", err)
	}
	fmt.Fprintf(o.ErrOut, "Private key written to file %s\n", keyFileName)

	// Build CertificateRequest with name as specified by argument
	req, err := buildCertificateRequest(crt, keyData, crName)
	if err != nil {
		return fmt.Errorf("error when building CertificateRequest: %w", err)
	}

	ns := crt.Namespace
	if ns == "" {
		ns = o.Namespace
	}
	req, err = o.CMClient.CertmanagerV1().CertificateRequests(ns).Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating CertificateRequest: %w", err)
	}
	fmt.Fprintf(o.ErrOut, "CertificateRequest %s has been created in namespace %s\n", req.Name, req.Namespace)

	if o.FetchCert {
		fmt.Fprintf(o.ErrOut, "CertificateRequest %v in namespace %v has not been signed yet. Wait until it is signed...\n",
			req.Name, req.Namespace)
		err = wait.Poll(time.Second, o.Timeout, func() (done bool, err error) {
			req, err = o.CMClient.CertmanagerV1().CertificateRequests(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			return apiutil.CertificateRequestHasCondition(req, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
			}) && len(req.Status.Certificate) > 0, nil
		})
		if err != nil {
			return fmt.Errorf("error when waiting for CertificateRequest to be signed: %w", err)
		}
		fmt.Fprintf(o.ErrOut, "CertificateRequest %v in namespace %v has been signed\n", req.Name, req.Namespace)

		// Fetch x509 certificate and store to file
		actualCertFileName := req.Name + ".crt"
		if o.CertFileName != "" {
			actualCertFileName = o.CertFileName
		}
		err = fetchCertificateFromCR(req, actualCertFileName)
		if err != nil {
			return fmt.Errorf("error when writing certificate to file: %w", err)
		}
		fmt.Fprintf(o.ErrOut, "Certificate written to file %s\n", actualCertFileName)
	}

	return nil
}

// Builds a CertificateRequest
func buildCertificateRequest(crt *cmapi.Certificate, pk []byte, crName string) (*cmapi.CertificateRequest, error) {
	csrPEM, err := generateCSR(crt, pk)
	if err != nil {
		return nil, err
	}

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        crName,
			Annotations: crt.Annotations,
			Labels:      crt.Labels,
		},
		Spec: cmapi.CertificateRequestSpec{
			Request:   csrPEM,
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

// fetchCertificateFromCR fetches the x509 certificate from a CR and stores the
// certificate in file specified by certFilename. Assumes CR is ready,
// otherwise returns error.
func fetchCertificateFromCR(req *cmapi.CertificateRequest, certFileName string) error {
	// If CR not ready yet, error
	if !apiutil.CertificateRequestHasCondition(req, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) || len(req.Status.Certificate) == 0 {
		return errors.New("CertificateRequest is not ready yet, unable to fetch certificate")
	}

	// Store certificate to file
	err := os.WriteFile(certFileName, req.Status.Certificate, 0600)
	if err != nil {
		return fmt.Errorf("error when writing certificate to file: %w", err)
	}

	return nil
}
