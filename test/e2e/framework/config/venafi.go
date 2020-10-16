/*
Copyright 2018 The Jetstack cert-manager contributors.

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

// Venafi global configuration for Venafi TPP/Cloud instances
type Venafi struct {
	TPP   VenafiTPPConfiguration
	Cloud VenafiCloudConfiguration
}

type VenafiTPPConfiguration struct {
	URL         string
	Zone        string
	Username    string
	Password    string
	AccessToken string
}

type VenafiCloudConfiguration struct {
	Zone     string
	APIToken string
}

func (v *Venafi) AddFlags(fs *flag.FlagSet) {
	v.TPP.AddFlags(fs)
	v.Cloud.AddFlags(fs)
}

func (v *Venafi) Validate() []error {
	return append(v.TPP.Validate(), v.Cloud.Validate()...)
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
