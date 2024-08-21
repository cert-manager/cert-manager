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

package apiserver

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	utilversion "k8s.io/apiserver/pkg/util/version"
	restclient "k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmopenapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/openapi"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/registry/challengepayload"
)

var (
	Scheme = runtime.NewScheme()
	Codecs = serializer.NewCodecFactory(Scheme)
)

func init() {
	utilruntime.Must(whapi.AddToScheme(Scheme))

	// we need to add the options to empty v1
	// TODO fix the server code to avoid this
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})

	// TODO: keep the generic API server from wanting this
	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	Scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)
}

type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

type ExtraConfig struct {
	// SolverGroup is the API name for solvers configured in this apiserver.
	// This should typically be something like 'acmesolvers.example.org'
	SolverGroup string

	// Solvers is a list of challenge solvers registered for this apiserver.
	Solvers []webhook.Solver
}

// ChallengeServer contains state for a webhook cluster apiserver.
type ChallengeServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig

	restConfig *restclient.Config
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *Config) Complete() CompletedConfig {
	c.GenericConfig.EffectiveVersion = utilversion.NewEffectiveVersion("1.1")
	c.GenericConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(cmopenapi.GetOpenAPIDefinitions, openapi.NewDefinitionNamer(Scheme))
	c.GenericConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(cmopenapi.GetOpenAPIDefinitions, openapi.NewDefinitionNamer(Scheme))

	return CompletedConfig{&completedConfig{
		c.GenericConfig.Complete(),
		&c.ExtraConfig,
		c.GenericConfig.ClientConfig,
	}}
}

// New returns a new instance of apiserver from the given config. Each of the
// configured solvers will have an API GroupVersion registered with the new
// apiserver and will have its Initialize function passed as post-start hook
// with the server.
func (c completedConfig) New() (*ChallengeServer, error) {
	genericServer, err := c.GenericConfig.New("challenge-server", genericapiserver.NewEmptyDelegate()) // completion is done in Complete, no need for a second time
	if err != nil {
		return nil, err
	}

	s := &ChallengeServer{
		GenericAPIServer: genericServer,
	}

	// TODO we're going to need a later k8s.io/apiserver so that we can get discovery to list a different group version for
	// our endpoint which we'll use to back some custom storage which will consume the AdmissionReview type and give back the correct response
	apiGroupInfo := genericapiserver.APIGroupInfo{
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		// TODO unhardcode this.  It was hardcoded before, but we need to re-evaluate
		OptionsExternalVersion: &schema.GroupVersion{Version: "v1"},
		Scheme:                 Scheme,
		ParameterCodec:         metav1.ParameterCodec,
		NegotiatedSerializer:   Codecs,
	}

	for _, solver := range solversByName(c.ExtraConfig.Solvers...) {
		gvr := metav1.GroupVersionResource{
			Group:    c.ExtraConfig.SolverGroup,
			Version:  "v1alpha1",
			Resource: solver.Name(),
		}

		challengeHandler := challengepayload.NewREST(solver)

		apiGroupInfo.PrioritizedVersions = appendUniqueGroupVersion(apiGroupInfo.PrioritizedVersions, schema.GroupVersion{
			Group:   gvr.Group,
			Version: gvr.Version,
		})

		v1alpha1storage, ok := apiGroupInfo.VersionedResourcesStorageMap[gvr.Version]
		if !ok {
			v1alpha1storage = map[string]rest.Storage{}
		}
		v1alpha1storage[gvr.Resource] = challengeHandler
		apiGroupInfo.VersionedResourcesStorageMap[gvr.Version] = v1alpha1storage
	}
	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, fmt.Errorf("error installing APIGroup for solvers: %w", err)
	}

	for i := range c.ExtraConfig.Solvers {
		solver := c.ExtraConfig.Solvers[i]
		postStartName := postStartHookName(solver)
		if len(postStartName) == 0 {
			continue
		}
		s.GenericAPIServer.AddPostStartHookOrDie(postStartName,
			func(context genericapiserver.PostStartHookContext) error {
				return solver.Initialize(c.restConfig, context.Done())
			},
		)
	}

	return s, nil
}

func postStartHookName(hook webhook.Solver) string {
	var ns []string
	ns = append(ns, fmt.Sprintf("solver-%s", hook.Name()))
	if len(ns) == 0 {
		return ""
	}
	return strings.Join(append(ns, "init"), "-")
}

func appendUniqueGroupVersion(slice []schema.GroupVersion, elems ...schema.GroupVersion) []schema.GroupVersion {
	m := map[schema.GroupVersion]bool{}
	for _, gv := range slice {
		m[gv] = true
	}
	for _, e := range elems {
		m[e] = true
	}
	out := make([]schema.GroupVersion, 0, len(m))
	for gv := range m {
		out = append(out, gv)
	}
	return out
}

func solversByName(solvers ...webhook.Solver) map[string]webhook.Solver {
	ret := map[string]webhook.Solver{}

	for _, s := range solvers {
		ret[s.Name()] = s
	}

	return ret
}
