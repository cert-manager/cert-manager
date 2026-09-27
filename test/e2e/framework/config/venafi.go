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

package config

import (
	"flag"
	"os"
)

// Venafi global configuration for Venafi TPP/Cloud/NGTS instances
type Venafi struct {
	TPP   VenafiTPPConfiguration
	Cloud VenafiCloudConfiguration
	NGTS  VenafiNGTSConfiguration
}

type VenafiTPPConfiguration struct {
	URL         string
	Zone        string
	Username    string
	Password    string // #nosec G117 -- test config only
	AccessToken string // #nosec G117 -- test config only
}

type VenafiCloudConfiguration struct {
	Zone     string
	APIToken string // #nosec G117 -- test config only
}

type VenafiNGTSConfiguration struct {
	Zone          string
	TokenEndpoint string
	TSGID         string
	ClientID      string // #nosec G117 -- test config only
	ClientSecret  string // #nosec G117 -- test config only
}

func (v *Venafi) AddFlags(fs *flag.FlagSet) {
	v.TPP.AddFlags(fs)
	v.Cloud.AddFlags(fs)
	v.NGTS.AddFlags(fs)
}

func (v *Venafi) Validate() []error {
	return append(append(v.TPP.Validate(), v.Cloud.Validate()...), v.NGTS.Validate()...)
}

func (v *VenafiTPPConfiguration) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&v.URL, "global.venafi-tpp-url", os.Getenv("VENAFI_TPP_URL"), "URL of the Venafi TPP instance to use during tests")
	fs.StringVar(&v.Zone, "global.venafi-tpp-zone", os.Getenv("VENAFI_TPP_ZONE"), "Zone to use during Venafi TPP end-to-end tests")
	fs.StringVar(&v.Username, "global.venafi-tpp-username", os.Getenv("VENAFI_TPP_USERNAME"), "Username to use when authenticating with the Venafi TPP instance")
	fs.StringVar(&v.Password, "global.venafi-tpp-password", os.Getenv("VENAFI_TPP_PASSWORD"), "Password to use when authenticating with the Venafi TPP instance")
	fs.StringVar(&v.AccessToken, "global.venafi-tpp-access-token", os.Getenv("VENAFI_TPP_ACCESS_TOKEN"), "Access token to use when authenticating with the Venafi TPP instance")
}

func (v *VenafiTPPConfiguration) Validate() []error {
	return nil
}

func (v *VenafiCloudConfiguration) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&v.Zone, "global.venafi-cloud-zone", os.Getenv("VENAFI_CLOUD_ZONE"), "Zone to use during Venafi Cloud end-to-end tests")
	fs.StringVar(&v.APIToken, "global.venafi-cloud-apitoken", os.Getenv("VENAFI_CLOUD_APITOKEN"), "API token to use when authenticating with the Venafi Cloud instance")
}

func (v *VenafiCloudConfiguration) Validate() []error {
	return nil
}

func (v *VenafiNGTSConfiguration) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&v.Zone, "global.venafi-ngts-zone", os.Getenv("VENAFI_NGTS_ZONE"), "Zone (certificate policy template) to use during Venafi NGTS end-to-end tests")
	fs.StringVar(&v.TokenEndpoint, "global.venafi-ngts-token-endpoint", os.Getenv("VENAFI_NGTS_TOKEN_ENDPOINT"), "OAuth 2.0 token endpoint URL for Venafi NGTS (optional, defaults to https://auth.apps.paloaltonetworks.com/oauth2/access_token)")
	fs.StringVar(&v.TSGID, "global.venafi-ngts-tsg-id", os.Getenv("VENAFI_NGTS_TSG_ID"), "Tenant Service Group ID for Venafi NGTS, e.g. 1234567890")
	fs.StringVar(&v.ClientID, "global.venafi-ngts-client-id", os.Getenv("VENAFI_NGTS_CLIENT_ID"), "OAuth 2.0 Client ID for Venafi NGTS")
	fs.StringVar(&v.ClientSecret, "global.venafi-ngts-client-secret", os.Getenv("VENAFI_NGTS_CLIENT_SECRET"), "OAuth 2.0 Client Secret for Venafi NGTS")
}

func (v *VenafiNGTSConfiguration) Validate() []error {
	return nil
}
