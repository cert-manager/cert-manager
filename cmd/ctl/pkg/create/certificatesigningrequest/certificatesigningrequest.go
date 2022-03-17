/*
Copyright 2021 The cert-manager Authors.

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

package certificatesigningrequest

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	"github.com/spf13/cobra"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/discovery"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/ctl"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var (
	long = templates.LongDesc(i18n.T(`
Experimental. Only supported for Kubernetes versions 1.19+. Requires
cert-manager versions 1.4+ with experimental controllers enabled.

Create a new CertificateSigningRequest resource based on a Certificate resource, by generating a private key locally and create a 'certificate signing request' to be submitted to a cert-manager Issuer.`))

	example = templates.Examples(i18n.T(build.WithTemplate(`
# Create a CertificateSigningRequest with the name 'my-csr', saving the private key in a file named 'my-cr.key'.
{{.BuildName}} x create certificatesigningrequest my-csr --from-certificate-file my-certificate.yaml

# Create a CertificateSigningRequest and store private key in file 'new.key'.
{{.BuildName}} x create certificatesigningrequest my-csr --from-certificate-file my-certificate.yaml --output-key-file new.key

# Create a CertificateSigningRequest, wait for it to be signed for up to 5 minutes (default) and store the x509 certificate in file 'new.crt'.
{{.BuildName}} x create csr my-cr -f my-certificate.yaml -c new.crt -w

# Create a CertificateSigningRequest, wait for it to be signed for up to 20 minutes and store the x509 certificate in file 'my-cr.crt'.
{{.BuildName}} x create csr my-cr --from-certificate-file my-certificate.yaml --fetch-certificate --timeout 20m
`)))
)

var (
	// Dedicated scheme used by the ctl tool that has the internal cert-manager types,
	// and their conversion functions registered
	scheme = ctl.Scheme
)

// Options is a struct to support create certificatesigningrequest command
type Options struct {
	// Name of file that the generated private key will be stored in If not
	// specified, the private key will be written to '<NameOfCSR>.key'.
	KeyFilename string

	// If true, will wait for CertificateSigingRequest to be ready to store the
	// x509 certificate in a file.
	// Command will block until CertificateSigningRequest is ready or timeout as
	// specified by Timeout happens.
	FetchCert bool

	// Name of file that the generated x509 certificate will be stored in if
	// --fetch-certificate flag is set If not specified, the private key will be
	// written to '<NameOfCSR>.crt'.
	CertFileName string

	// Path to a file containing a Certificate resource used as a template when
	// generating the CertificateSigningRequest resource.
	// Required.
	InputFilename string

	// Length of time the command blocks to wait on CertificateSigningRequest to
	// be ready if --fetch-certificate flag is set If not specified, default
	// value is 5 minutes.
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

// NewCmdCreateCSR returns a cobra command for create CertificateSigningRequest
func NewCmdCreateCSR(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:               "certificatesigningrequest",
		Aliases:           []string{"csr"},
		Short:             "Create a Kubernetes CertificateSigningRequest resource, using a Certificate resource as a template",
		Long:              long,
		Example:           example,
		ValidArgsFunction: factory.ValidArgsListCertificateSigningRequests(ctx, &o.Factory),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Run(ctx, args))
		},
	}
	cmd.Flags().StringVarP(&o.InputFilename, "from-certificate-file", "f", o.InputFilename,
		"Path to a file containing a Certificate resource used as a template when generating the CertificateSigningRequest resource")
	cmd.Flags().StringVarP(&o.KeyFilename, "output-key-file", "k", o.KeyFilename,
		"Name of file that the generated private key will be written to")
	cmd.Flags().StringVarP(&o.CertFileName, "output-certificate-file", "c", o.CertFileName,
		"Name of the file the certificate is to be stored in")
	cmd.Flags().BoolVarP(&o.FetchCert, "fetch-certificate", "w", o.FetchCert,
		"If set to true, command will wait for CertificateSigningRequest to be signed to store x509 certificate in a file")
	cmd.Flags().DurationVar(&o.Timeout, "timeout", 5*time.Minute,
		"Time before timeout when waiting for CertificateSigningRequest to be signed, must include unit, e.g. 10m or 1h")

	o.Factory = factory.New(ctx, cmd)

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(args []string) error {
	if len(args) < 1 {
		return errors.New("the name of the CertificateSigningRequest to be created has to be provided as argument")
	}
	if len(args) > 1 {
		return errors.New("only one argument can be passed in: the name of the CertificateSigningRequest")
	}

	if o.InputFilename == "" {
		return errors.New("the path to a YAML manifest of a Certificate resource cannot be empty, please specify by using --from-certificate-file or -f flag")
	}

	if o.KeyFilename != "" && o.CertFileName != "" && o.KeyFilename == o.CertFileName {
		return errors.New("the file to store private key cannot be the same as the file to store certificate")
	}

	if !o.FetchCert && o.CertFileName != "" {
		return errors.New("cannot specify file to store certificate if not waiting for and fetching certificate, please set --fetch-certificate or -w flag")
	}

	return nil
}

// Run executes create certificatesigningrequest command
func (o *Options) Run(ctx context.Context, args []string) error {
	builder := new(resource.Builder)

	// Read file as internal API version
	r := builder.
		WithScheme(scheme, schema.GroupVersion{Group: cmapi.SchemeGroupVersion.Group, Version: runtime.APIVersionInternal}).
		LocalParam(true).ContinueOnError().
		FilenameParam(false, &resource.FilenameOptions{Filenames: []string{o.InputFilename}}).Flatten().Do()

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
		return fmt.Errorf("failed to convert object into version v1: %s", err)
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

	if len(crt.Namespace) == 0 {
		// Default to the 'default' Namespace if no Namespaced defined on the
		// Certificate
		crt.Namespace = "default"
	}

	signer, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return fmt.Errorf("error when generating new private key for CertificateSigningRequest: %s", err)
	}

	keyPEM, err := pki.EncodePrivateKey(signer, crt.Spec.PrivateKey.Encoding)
	if err != nil {
		return fmt.Errorf("failed to encode new private key for CertificateSigningRequest: %s", err)
	}

	csrName := args[0]

	// Storing private key to file
	keyFileName := csrName + ".key"
	if o.KeyFilename != "" {
		keyFileName = o.KeyFilename
	}
	if err := os.WriteFile(keyFileName, keyPEM, 0600); err != nil {
		return fmt.Errorf("error when writing private key to file: %s", err)
	}
	fmt.Fprintf(o.Out, "Private key written to file %s\n", keyFileName)

	signerName, err := buildSignerName(o.KubeClient.Discovery(), crt)
	if err != nil {
		return fmt.Errorf("failed to build signerName from Certificate: %s", err)
	}

	// Build CertificateSigningRequest with name as specified by argument
	req, err := buildCertificateSigningRequest(crt, keyPEM, csrName, signerName)
	if err != nil {
		return fmt.Errorf("error when building CertificateSigningRequest: %s", err)
	}

	req, err = o.KubeClient.CertificatesV1().CertificateSigningRequests().Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating CertificateSigningRequest: %s", err)
	}
	fmt.Fprintf(o.Out, "CertificateSigningRequest %s has been created\n", req.Name)

	if o.FetchCert {
		fmt.Fprintf(o.Out, "CertificateSigningRequest %s has not been signed yet. Wait until it is signed...\n", req.Name)

		err = wait.Poll(time.Second, o.Timeout, func() (done bool, err error) {
			req, err = o.KubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, req.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return len(req.Status.Certificate) > 0, nil
		})
		if err != nil {
			return fmt.Errorf("error when waiting for CertificateSigningRequest to be signed: %s", err)
		}

		fmt.Fprintf(o.Out, "CertificateSigningRequest %s has been signed\n", req.Name)

		// Fetch x509 certificate and store to file
		actualCertFileName := req.Name + ".crt"
		if o.CertFileName != "" {
			actualCertFileName = o.CertFileName
		}

		err = storeCertificate(req, actualCertFileName)
		if err != nil {
			return fmt.Errorf("error when writing certificate to file: %s", err)
		}
		fmt.Fprintf(o.Out, "Certificate written to file %s\n", actualCertFileName)
	}

	return nil
}

// buildSignerName with generate a Kubernetes CertificateSigningRequest signer
// name, based on the input Certificate's IssuerRef. This function will use the
// Discovery API to fetch the resource definition of the referenced Issuer
// Kind.
// The signer name format follows that of cert-manager.
func buildSignerName(client discovery.DiscoveryInterface, crt *cmapi.Certificate) (string, error) {
	targetGroup := crt.Spec.IssuerRef.Group
	if len(targetGroup) == 0 {
		targetGroup = certmanager.GroupName
	}

	targetKind := crt.Spec.IssuerRef.Kind
	if len(targetKind) == 0 {
		targetKind = cmapi.IssuerKind
	}

	grouplist, err := client.ServerGroups()
	if err != nil {
		return "", err
	}

	for _, group := range grouplist.Groups {
		if group.Name != targetGroup {
			continue
		}

		for _, version := range group.Versions {
			resources, err := client.ServerResourcesForGroupVersion(version.GroupVersion)
			if err != nil {
				return "", err
			}

			for _, resource := range resources.APIResources {
				if resource.Kind != targetKind {
					continue
				}

				if resource.Namespaced {
					return fmt.Sprintf("%s.%s/%s.%s", resource.Name, targetGroup, crt.Namespace, crt.Spec.IssuerRef.Name), nil
				}

				return fmt.Sprintf("%s.%s/%s", resource.Name, targetGroup, crt.Spec.IssuerRef.Name), nil
			}
		}
	}

	return "", fmt.Errorf("issuer references a resource definition which does not exist group=%s kind=%s",
		targetGroup, targetKind)
}

// Builds a CertificateSigningRequest
func buildCertificateSigningRequest(crt *cmapi.Certificate, pk []byte, crName, signerName string) (*certificatesv1.CertificateSigningRequest, error) {
	csrPEM, err := generateCSR(crt, pk)
	if err != nil {
		return nil, err
	}

	ku, eku, err := pki.BuildKeyUsages(crt.Spec.Usages, crt.Spec.IsCA)
	if err != nil {
		return nil, err
	}

	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        crName,
			Annotations: crt.Annotations,
			Labels:      crt.Labels,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csrPEM,
			SignerName: signerName,
			Usages:     append(apiutil.KubeKeyUsageStrings(ku), apiutil.KubeExtKeyUsageStrings(eku)...),
		},
	}

	if csr.Annotations == nil {
		csr.Annotations = make(map[string]string)
	}
	csr.Annotations[experimentalapi.CertificateSigningRequestIsCAAnnotationKey] = strconv.FormatBool(crt.Spec.IsCA)
	if crt.Spec.Duration != nil {
		duration := crt.Spec.Duration.Duration
		csr.Annotations[experimentalapi.CertificateSigningRequestDurationAnnotationKey] = duration.String()
		seconds := int32(duration.Seconds())  // technically this could overflow but I do not think it matters
		csr.Spec.ExpirationSeconds = &seconds // if this is less than 600, the API server will fail the request
	}

	return csr, nil
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

// storeCertificate fetches the x509 certificate from a
// CertificateSigningRequest and stores the certificate in file specified by
// certFilename. Assumes request is signed, otherwise returns error.
func storeCertificate(req *certificatesv1.CertificateSigningRequest, fileName string) error {
	// If request not signed yet, error
	if len(req.Status.Certificate) == 0 {
		return errors.New("CertificateSigningRequest is not ready yet, unable to fetch certificate")
	}

	// Store certificate to file
	err := os.WriteFile(fileName, req.Status.Certificate, 0600)
	if err != nil {
		return fmt.Errorf("error when writing certificate to file: %s", err)
	}

	return nil
}
