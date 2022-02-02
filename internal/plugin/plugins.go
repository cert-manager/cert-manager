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

package plugin

import (
	"github.com/cert-manager/cert-manager/internal/plugin/admission/apideprecation"
	certificaterequestapproval "github.com/cert-manager/cert-manager/internal/plugin/admission/certificaterequest/approval"
	certificaterequestidentity "github.com/cert-manager/cert-manager/internal/plugin/admission/certificaterequest/identity"
	"github.com/cert-manager/cert-manager/internal/plugin/admission/resourcevalidation"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
	"k8s.io/apimachinery/pkg/util/sets"
)

var AllOrderedPlugins = []string{
	apideprecation.PluginName,
	resourcevalidation.PluginName,
	certificaterequestidentity.PluginName,
	certificaterequestapproval.PluginName,
}

func RegisterAllPlugins(plugins *admission.Plugins) {
	apideprecation.Register(plugins)
	certificaterequestidentity.Register(plugins)
	certificaterequestapproval.Register(plugins)
	resourcevalidation.Register(plugins)
}

func DefaultOnAdmissionPlugins() sets.String {
	return sets.NewString(
		apideprecation.PluginName,
		resourcevalidation.PluginName,
		certificaterequestidentity.PluginName,
		certificaterequestapproval.PluginName,
	)
}

// DefaultOffAdmissionPlugins gets admission plugins off by default for the webhook.
func DefaultOffAdmissionPlugins() sets.String {
	return sets.NewString(AllOrderedPlugins...).Difference(DefaultOnAdmissionPlugins())
}
