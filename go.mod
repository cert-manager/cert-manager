module github.com/jetstack/cert-manager

go 1.12

replace github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.4

replace golang.org/x/crypto => github.com/munnerz/crypto v0.0.0-20191203200931-e1844778daa5

require (
	github.com/Azure/azure-sdk-for-go v32.5.0+incompatible
	github.com/Azure/go-autorest/autorest v0.9.0
	github.com/Azure/go-autorest/autorest/adal v0.5.0
	github.com/Azure/go-autorest/autorest/to v0.3.0
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/Venafi/vcert v0.0.0-20200207035730-5a915d73be5d
	github.com/aws/aws-sdk-go v1.24.1
	github.com/cloudflare/cloudflare-go v0.8.5
	github.com/cpu/goacmedns v0.0.0-20180701200144-565ecf2a84df
	github.com/digitalocean/godo v1.29.0
	github.com/go-logr/logr v0.1.0
	github.com/go-logr/zapr v0.1.1 // indirect
	github.com/google/gofuzz v1.0.0
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gorilla/mux v1.6.2
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/kr/pretty v0.1.0
	github.com/mattbaird/jsonpatch v0.0.0-20171005235357-81af80346b1a
	github.com/miekg/dns v0.0.0-20170721150254-0f3adef2e220
	github.com/munnerz/crd-schema-fuzz v0.0.0-20191114184610-fbd148d44a0a
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	github.com/pavel-v-chernykh/keystore-go v2.1.0+incompatible
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v1.0.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20191202143827-86a70503ff7e
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	google.golang.org/api v0.4.0
	gopkg.in/ini.v1 v1.52.0 // indirect
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.17.3
	k8s.io/apiextensions-apiserver v0.17.3
	k8s.io/apimachinery v0.17.3
	k8s.io/apiserver v0.17.3
	k8s.io/client-go v0.17.3
	k8s.io/code-generator v0.17.3
	k8s.io/component-base v0.17.3
	k8s.io/klog v1.0.0
	k8s.io/kube-aggregator v0.17.3
	k8s.io/kube-openapi v0.0.0-20191107075043-30be4d16710a
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f
	sigs.k8s.io/controller-runtime v0.5.1-0.20200307095134-d0de78d9f1c1
	sigs.k8s.io/controller-tools v0.2.5
	sigs.k8s.io/testing_frameworks v0.1.2
	software.sslmate.com/src/go-pkcs12 v0.0.0-20180114231543-2291e8f0f237
)
