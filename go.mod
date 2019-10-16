module github.com/jetstack/cert-manager

go 1.12

// Pin k8s.io/* dependencies to kubernetes-1.16.0
replace (
	k8s.io/api => k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20190918161926-8f644eb6e783
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20190918160949-bfa5e2e684ad
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190918160344-1fbdaa4c8d90
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
	k8s.io/component-base => k8s.io/component-base v0.0.0-20190918160511-547f6c5d7090
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20190918161219-8c8f079fddc3
)

require (
	cloud.google.com/go v0.38.0
	github.com/Azure/azure-sdk-for-go v32.5.0+incompatible
	github.com/Azure/go-autorest/autorest v0.9.0
	github.com/Azure/go-autorest/autorest/adal v0.5.0
	github.com/Azure/go-autorest/autorest/to v0.3.0
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/Microsoft/go-winio v0.4.12 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/SAP/go-hdb v0.14.1 // indirect
	github.com/SermoDigital/jose v0.9.1 // indirect
	github.com/Venafi/vcert v0.0.0-20190613103158-62139eb19b25
	github.com/armon/go-metrics v0.0.0-20180917152333-f0300d1749da // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/aws/aws-sdk-go v1.24.1
	github.com/bitly/go-hostpool v0.0.0-20171023180738-a3a6125de932 // indirect
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/cenkalti/backoff v2.1.1+incompatible // indirect
	github.com/cloudflare/cloudflare-go v0.8.5
	github.com/containerd/continuity v0.0.0-20181203112020-004b46473808 // indirect
	github.com/cpu/goacmedns v0.0.0-20180701200144-565ecf2a84df
	github.com/denisenkom/go-mssqldb v0.0.0-20190412130859-3b1d194e553a // indirect
	github.com/digitalocean/godo v1.6.0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/duosecurity/duo_api_golang v0.0.0-20190308151101-6c680f768e74 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/go-logr/logr v0.1.0
	github.com/go-logr/zapr v0.1.1 // indirect
	github.com/go-openapi/spec v0.19.2
	github.com/go-sql-driver/mysql v1.4.1 // indirect
	github.com/gocql/gocql v0.0.0-20190402132108-0e1d5de854df // indirect
	github.com/google/btree v1.0.0 // indirect
	github.com/google/go-github v17.0.0+incompatible
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/gofuzz v1.0.0
	github.com/gorilla/mux v1.6.2
	github.com/gotestyourself/gotestyourself v2.2.0+incompatible // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-hclog v0.8.0 // indirect
	github.com/hashicorp/go-memdb v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.0.0 // indirect
	github.com/hashicorp/go-plugin v1.0.0 // indirect
	github.com/hashicorp/go-rootcerts v1.0.0 // indirect
	github.com/hashicorp/go-uuid v1.0.1 // indirect
	github.com/hashicorp/go-version v1.1.0 // indirect
	github.com/hashicorp/golang-math-big v0.0.0-20180316142257-561262b71329 // indirect
	github.com/hashicorp/vault v0.9.6
	github.com/jefferai/jsonx v1.0.0 // indirect
	github.com/keybase/go-crypto v0.0.0-20190403132359-d65b6b94177f // indirect
	github.com/kr/pretty v0.1.0
	github.com/lib/pq v1.0.0 // indirect
	github.com/mattbaird/jsonpatch v0.0.0-20171005235357-81af80346b1a
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/mgutz/logxi v0.0.0-20161027140823-aebf8a7d67ab // indirect
	github.com/miekg/dns v0.0.0-20170721150254-0f3adef2e220
	github.com/mitchellh/copystructure v1.0.0 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20190414153302-2ae31c8b6b30 // indirect
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/ory/dockertest v3.3.4+incompatible // indirect
	github.com/pascaldekloe/goe v0.1.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.3-0.20190127221311-3c4408c8b829
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/sethgrid/pester v0.0.0-20190127155807-68a33a018ad0 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.3
	github.com/stretchr/testify v1.3.0
	github.com/tent/http-link-go v0.0.0-20130702225549-ac974c61c2f9 // indirect
	golang.org/x/crypto v0.0.0-20190611184440-5c40567a22f8
	golang.org/x/net v0.0.0-20190812203447-cdfb69ac37fc
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	google.golang.org/api v0.4.0
	gopkg.in/ini.v1 v1.42.0 // indirect
	gopkg.in/mgo.v2 v2.0.0-20180705113604-9856a29383ce // indirect
	gopkg.in/ory-am/dockertest.v3 v3.3.4 // indirect
	k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apiextensions-apiserver v0.0.0-20190918161926-8f644eb6e783
	k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/apiserver v0.0.0-20190918160949-bfa5e2e684ad
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
	k8s.io/component-base v0.0.0-20190918160511-547f6c5d7090
	k8s.io/klog v0.4.0
	k8s.io/kube-aggregator v0.0.0-20190222095010-0b78038fe9e5
	k8s.io/kube-openapi v0.0.0-20190816220812-743ec37842bf
	k8s.io/utils v0.0.0-20190801114015-581e00157fb1
	launchpad.net/gocheck v0.0.0-20140225173054-000000000087 // indirect
	sigs.k8s.io/controller-runtime v0.2.0-beta.4
	sigs.k8s.io/controller-tools v0.2.0-beta.4
	sigs.k8s.io/testing_frameworks v0.1.1
)

replace sigs.k8s.io/controller-runtime => github.com/munnerz/controller-runtime v0.1.8-0.20190907105316-d02b94982e57

replace github.com/evanphx/json-patch => github.com/evanphx/json-patch v0.0.0-20190203023257-5858425f7550

replace github.com/munnerz/goautoneg => github.com/munnerz/goautoneg v0.0.0-20190414153302-2ae31c8b6b30

replace sigs.k8s.io/controller-tools => github.com/munnerz/controller-tools v0.1.10-0.20191002183933-2bcde27e8caa
