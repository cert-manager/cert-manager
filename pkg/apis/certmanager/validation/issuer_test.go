package validation

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

var (
	validCloudDNSProvider = v1alpha1.ACMEIssuerDNS01ProviderCloudDNS{
		ServiceAccount: validSecretKeyRef,
		Project:        "valid",
	}
	validSecretKeyRef = v1alpha1.SecretKeySelector{
		LocalObjectReference: v1alpha1.LocalObjectReference{
			Name: "valid",
		},
		Key: "validkey",
	}
	validCloudflareProvider = v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
		APIKey: validSecretKeyRef,
		Email:  "valid",
	}
	validACMEIssuer = v1alpha1.ACMEIssuer{
		Email:      "valid-email",
		Server:     "valid-server",
		PrivateKey: validSecretKeyRef,
	}
	validVaultIssuer = v1alpha1.VaultIssuer{
		Auth: v1alpha1.VaultAuth{
			TokenSecretRef: validSecretKeyRef,
		},
		Server: "something",
		Path:   "a/b/c",
	}
)

func TestValidateVaultIssuerConfig(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		spec *v1alpha1.VaultIssuer
		errs []*field.Error
	}{
		"valid vault issuer": {
			spec: &validVaultIssuer,
		},
		"vault issuer with missing fields": {
			spec: &v1alpha1.VaultIssuer{},
			errs: []*field.Error{
				field.Required(fldPath.Child("server"), ""),
				field.Required(fldPath.Child("path"), ""),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateVaultIssuerConfig(s.spec, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateACMEIssuerConfig(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		spec *v1alpha1.ACMEIssuer
		errs []*field.Error
	}{
		"valid acme issuer": {
			spec: &validACMEIssuer,
		},
		"acme issuer with missing fields": {
			spec: &v1alpha1.ACMEIssuer{},
			errs: []*field.Error{
				field.Required(fldPath.Child("email"), "email address is a required field"),
				field.Required(fldPath.Child("privateKey", "name"), "private key secret name is a required field"),
				field.Required(fldPath.Child("server"), "acme server URL is a required field"),
			},
		},
		"acme issuer with invalid dns01 config": {
			spec: &v1alpha1.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				DNS01: &v1alpha1.ACMEIssuerDNS01Config{
					Providers: []v1alpha1.ACMEIssuerDNS01Provider{
						{
							Name: "valid-name",
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("dns01", "providers").Index(0), "at least one provider must be configured"),
			},
		},
		"acme issuer with valid dns01 config": {
			spec: &v1alpha1.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				DNS01: &v1alpha1.ACMEIssuerDNS01Config{
					Providers: []v1alpha1.ACMEIssuerDNS01Provider{
						{
							Name:     "valid-name",
							CloudDNS: &validCloudDNSProvider,
						},
					},
				},
			},
		},
		"acme issuer with valid http01 config": {
			spec: &v1alpha1.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				HTTP01:     &v1alpha1.ACMEIssuerHTTP01Config{},
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateACMEIssuerConfig(s.spec, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateIssuerSpec(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		spec *v1alpha1.IssuerSpec
		errs []*field.Error
	}{
		"valid ca issuer": {
			spec: &v1alpha1.IssuerSpec{
				IssuerConfig: v1alpha1.IssuerConfig{
					CA: &v1alpha1.CAIssuer{
						SecretName: "valid",
					},
				},
			},
		},
		"ca issuer without secret name specified": {
			spec: &v1alpha1.IssuerSpec{
				IssuerConfig: v1alpha1.IssuerConfig{
					CA: &v1alpha1.CAIssuer{},
				},
			},
			errs: []*field.Error{field.Required(fldPath.Child("ca", "secretName"), "")},
		},
		"valid self signed issuer": {
			spec: &v1alpha1.IssuerSpec{
				IssuerConfig: v1alpha1.IssuerConfig{
					SelfSigned: &v1alpha1.SelfSignedIssuer{},
				},
			},
		},
		"valid acme issuer": {
			spec: &v1alpha1.IssuerSpec{
				IssuerConfig: v1alpha1.IssuerConfig{
					ACME: &validACMEIssuer,
				},
			},
		},
		"valid vault issuer": {
			spec: &v1alpha1.IssuerSpec{
				IssuerConfig: v1alpha1.IssuerConfig{
					Vault: &validVaultIssuer,
				},
			},
		},
		"missing issuer config": {
			spec: &v1alpha1.IssuerSpec{
				IssuerConfig: v1alpha1.IssuerConfig{},
			},
			errs: []*field.Error{
				field.Required(fldPath, "at least one issuer must be configured"),
			},
		},
		"multiple issuers configured": {
			spec: &v1alpha1.IssuerSpec{
				IssuerConfig: v1alpha1.IssuerConfig{
					SelfSigned: &v1alpha1.SelfSignedIssuer{},
					CA: &v1alpha1.CAIssuer{
						SecretName: "valid",
					},
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("selfSigned"), "may not specify more than one issuer type"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateIssuerSpec(s.spec, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateACMEIssuerDNS01Config(t *testing.T) {
	fldPath := field.NewPath("")
	providersPath := fldPath.Child("providers")
	scenarios := map[string]struct {
		cfg  *v1alpha1.ACMEIssuerDNS01Config
		errs []*field.Error
	}{
		"missing name": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						CloudDNS: &validCloudDNSProvider,
					},
				},
			},
			errs: []*field.Error{field.Required(providersPath.Index(0).Child("name"), "name must be specified")},
		},
		"missing clouddns project": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "a name",
						CloudDNS: &v1alpha1.ACMEIssuerDNS01ProviderCloudDNS{
							ServiceAccount: validSecretKeyRef,
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(providersPath.Index(0).Child("clouddns", "project"), ""),
			},
		},
		"missing clouddns service account": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "a name",
						CloudDNS: &v1alpha1.ACMEIssuerDNS01ProviderCloudDNS{
							Project: "valid",
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(providersPath.Index(0).Child("clouddns", "serviceAccountSecretRef", "name"), "secret name is required"),
				field.Required(providersPath.Index(0).Child("clouddns", "serviceAccountSecretRef", "key"), "secret key is required"),
			},
		},
		"missing cloudflare token": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "a name",
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: "valid",
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(providersPath.Index(0).Child("cloudflare", "apiKeySecretRef", "name"), "secret name is required"),
				field.Required(providersPath.Index(0).Child("cloudflare", "apiKeySecretRef", "key"), "secret key is required"),
			},
		},
		"missing cloudflare email": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "a name",
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							APIKey: validSecretKeyRef,
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(providersPath.Index(0).Child("cloudflare", "email"), ""),
			},
		},
		"missing route53 region": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name:    "a name",
						Route53: &v1alpha1.ACMEIssuerDNS01ProviderRoute53{},
					},
				},
			},
			errs: []*field.Error{
				field.Required(providersPath.Index(0).Child("route53", "region"), ""),
			},
		},
		"missing provider config": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "a name",
					},
				},
			},
			errs: []*field.Error{
				field.Required(providersPath.Index(0), "at least one provider must be configured"),
			},
		},
		"missing azuredns config": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name:     "a name",
						AzureDNS: &v1alpha1.ACMEIssuerDNS01ProviderAzureDNS{},
					},
				},
			},
			errs: []*field.Error{
				field.Required(providersPath.Index(0).Child("azuredns", "clientSecretSecretRef", "name"), "secret name is required"),
				field.Required(providersPath.Index(0).Child("azuredns", "clientSecretSecretRef", "key"), "secret key is required"),
				field.Required(providersPath.Index(0).Child("azuredns", "clientID"), ""),
				field.Required(providersPath.Index(0).Child("azuredns", "subscriptionID"), ""),
				field.Required(providersPath.Index(0).Child("azuredns", "tenantID"), ""),
				field.Required(providersPath.Index(0).Child("azuredns", "resourceGroupName"), ""),
			},
		},
		"missing akamai config": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name:   "a name",
						Akamai: &v1alpha1.ACMEIssuerDNS01ProviderAkamai{},
					},
				},
			},
			errs: []*field.Error{
				field.Required(providersPath.Index(0).Child("akamai", "accessToken", "name"), "secret name is required"),
				field.Required(providersPath.Index(0).Child("akamai", "accessToken", "key"), "secret key is required"),
				field.Required(providersPath.Index(0).Child("akamai", "clientSecret", "name"), "secret name is required"),
				field.Required(providersPath.Index(0).Child("akamai", "clientSecret", "key"), "secret key is required"),
				field.Required(providersPath.Index(0).Child("akamai", "clientToken", "name"), "secret name is required"),
				field.Required(providersPath.Index(0).Child("akamai", "clientToken", "key"), "secret key is required"),
				field.Required(providersPath.Index(0).Child("akamai", "serviceConsumerDomain"), ""),
			},
		},
		"valid akamai config": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "a name",
						Akamai: &v1alpha1.ACMEIssuerDNS01ProviderAkamai{
							AccessToken:           validSecretKeyRef,
							ClientSecret:          validSecretKeyRef,
							ClientToken:           validSecretKeyRef,
							ServiceConsumerDomain: "abc",
						},
					},
				},
			},
			errs: []*field.Error{},
		},
		"multiple providers configured": {
			cfg: &v1alpha1.ACMEIssuerDNS01Config{
				Providers: []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name:       "a name",
						CloudDNS:   &validCloudDNSProvider,
						Cloudflare: &validCloudflareProvider,
					},
				},
			},
			errs: []*field.Error{
				field.Forbidden(providersPath.Index(0).Child("cloudflare"), "may not specify more than one provider type"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateACMEIssuerDNS01Config(s.cfg, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateSecretKeySelector(t *testing.T) {
	validName := v1alpha1.LocalObjectReference{"name"}
	validKey := "key"
	// invalidName := v1alpha1.LocalObjectReference{"-name-"}
	// invalidKey := "-key-"
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		isExpectedFailure bool
		selector          *v1alpha1.SecretKeySelector
		errs              []*field.Error
	}{
		"valid selector": {
			selector: &v1alpha1.SecretKeySelector{
				LocalObjectReference: validName,
				Key:                  validKey,
			},
		},
		// "invalid name": {
		// 	isExpectedFailure: true,
		// 	selector: &v1alpha1.SecretKeySelector{
		// 		LocalObjectReference: invalidName,
		// 		Key:                  validKey,
		// 	},
		// },
		// "invalid key": {
		// 	isExpectedFailure: true,
		// 	selector: &v1alpha1.SecretKeySelector{
		// 		LocalObjectReference: validName,
		// 		Key:                  invalidKey,
		// 	},
		// },
		"missing name": {
			selector: &v1alpha1.SecretKeySelector{
				Key: validKey,
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("name"), "secret name is required"),
			},
		},
		"missing key": {
			selector: &v1alpha1.SecretKeySelector{
				LocalObjectReference: validName,
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("key"), "secret key is required"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateSecretKeySelector(s.selector, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}
