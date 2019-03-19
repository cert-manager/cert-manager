package apiserver

import (
	"fmt"
	"strings"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"

	"github.com/openshift/generic-admission-server/pkg/registry/admissionreview"
)

var (
	Scheme = runtime.NewScheme()
	Codecs = serializer.NewCodecFactory(Scheme)
)

type AdmissionHook interface {
	// Initialize is called as a post-start hook
	Initialize(kubeClientConfig *restclient.Config, stopCh <-chan struct{}) error
}

type ValidatingAdmissionHook interface {
	AdmissionHook

	// ValidatingResource is the resource to use for hosting your admission webhook. If the hook implements
	// MutatingAdmissionHook as well, the two resources for validating and mutating admission must be different.
	// Note: this is (usually) not the same as the payload resource!
	ValidatingResource() (plural schema.GroupVersionResource, singular string)

	// Validate is called to decide whether to accept the admission request. The returned AdmissionResponse
	// must not use the Patch field.
	Validate(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse
}

type MutatingAdmissionHook interface {
	AdmissionHook

	// MutatingResource is the resource to use for hosting your admission webhook. If the hook implements
	// ValidatingAdmissionHook as well, the two resources for validating and mutating admission must be different.
	// Note: this is (usually) not the same as the payload resource!
	MutatingResource() (plural schema.GroupVersionResource, singular string)

	// Admit is called to decide whether to accept the admission request. The returned AdmissionResponse may
	// use the Patch field to mutate the object from the passed AdmissionRequest.
	Admit(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse
}

func init() {
	admissionv1beta1.AddToScheme(Scheme)

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
	AdmissionHooks []AdmissionHook
}

// AdmissionServer contains state for a Kubernetes cluster master/api server.
type AdmissionServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *Config) Complete() CompletedConfig {
	completedCfg := completedConfig{
		c.GenericConfig.Complete(),
		&c.ExtraConfig,
	}

	completedCfg.GenericConfig.Version = &version.Info{
		Major: "1",
		Minor: "1",
	}

	return CompletedConfig{&completedCfg}
}

// New returns a new instance of AdmissionServer from the given config.
func (c completedConfig) New() (*AdmissionServer, error) {
	genericServer, err := c.GenericConfig.New("admission-server", genericapiserver.NewEmptyDelegate()) // completion is done in Complete, no need for a second time
	if err != nil {
		return nil, err
	}

	s := &AdmissionServer{
		GenericAPIServer: genericServer,
	}

	inClusterConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, err
	}

	for _, versionMap := range admissionHooksByGroupThenVersion(c.ExtraConfig.AdmissionHooks...) {
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

		for _, admissionHooks := range versionMap {
			for i := range admissionHooks {
				admissionHook := admissionHooks[i]
				admissionResource, _ := admissionHook.Resource()
				admissionVersion := admissionResource.GroupVersion()

				// just overwrite the groupversion with a random one.  We don't really care or know.
				apiGroupInfo.PrioritizedVersions = appendUniqueGroupVersion(apiGroupInfo.PrioritizedVersions, admissionVersion)

				admissionReview := admissionreview.NewREST(admissionHook.Admission)
				v1alpha1storage, ok := apiGroupInfo.VersionedResourcesStorageMap[admissionVersion.Version]
				if !ok {
					v1alpha1storage = map[string]rest.Storage{}
				}
				v1alpha1storage[admissionResource.Resource] = admissionReview
				apiGroupInfo.VersionedResourcesStorageMap[admissionVersion.Version] = v1alpha1storage
			}
		}

		if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
			return nil, err
		}
	}

	for i := range c.ExtraConfig.AdmissionHooks {
		admissionHook := c.ExtraConfig.AdmissionHooks[i]
		postStartName := postStartHookName(admissionHook)
		if len(postStartName) == 0 {
			continue
		}
		s.GenericAPIServer.AddPostStartHookOrDie(postStartName,
			func(context genericapiserver.PostStartHookContext) error {
				return admissionHook.Initialize(inClusterConfig, context.StopCh)
			},
		)
	}

	return s, nil
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

func postStartHookName(hook AdmissionHook) string {
	var ns []string
	if mutatingHook, ok := hook.(MutatingAdmissionHook); ok {
		gvr, _ := mutatingHook.MutatingResource()
		ns = append(ns, fmt.Sprintf("mutating-%s.%s.%s", gvr.Resource, gvr.Version, gvr.Group))
	}
	if validatingHook, ok := hook.(ValidatingAdmissionHook); ok {
		gvr, _ := validatingHook.ValidatingResource()
		ns = append(ns, fmt.Sprintf("validating-%s.%s.%s", gvr.Resource, gvr.Version, gvr.Group))
	}
	if len(ns) == 0 {
		return ""
	}
	return strings.Join(append(ns, "init"), "-")
}

func admissionHooksByGroupThenVersion(admissionHooks ...AdmissionHook) map[string]map[string][]admissionHookWrapper {
	ret := map[string]map[string][]admissionHookWrapper{}

	for i := range admissionHooks {
		if mutatingHook, ok := admissionHooks[i].(MutatingAdmissionHook); ok {
			gvr, _ := mutatingHook.MutatingResource()
			group, ok := ret[gvr.Group]
			if !ok {
				group = map[string][]admissionHookWrapper{}
				ret[gvr.Group] = group
			}
			group[gvr.Version] = append(group[gvr.Version], mutatingAdmissionHookWrapper{mutatingHook})
		}
		if validatingHook, ok := admissionHooks[i].(ValidatingAdmissionHook); ok {
			gvr, _ := validatingHook.ValidatingResource()
			group, ok := ret[gvr.Group]
			if !ok {
				group = map[string][]admissionHookWrapper{}
				ret[gvr.Group] = group
			}
			group[gvr.Version] = append(group[gvr.Version], validatingAdmissionHookWrapper{validatingHook})
		}
	}

	return ret
}

// admissionHookWrapper wraps either a validating or mutating admission hooks, calling the respective resource and admission method.
type admissionHookWrapper interface {
	Resource() (plural schema.GroupVersionResource, singular string)
	Admission(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse
}

type mutatingAdmissionHookWrapper struct {
	hook MutatingAdmissionHook
}

func (h mutatingAdmissionHookWrapper) Resource() (plural schema.GroupVersionResource, singular string) {
	return h.hook.MutatingResource()
}

func (h mutatingAdmissionHookWrapper) Admission(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse {
	return h.hook.Admit(admissionSpec)
}

type validatingAdmissionHookWrapper struct {
	hook ValidatingAdmissionHook
}

func (h validatingAdmissionHookWrapper) Resource() (plural schema.GroupVersionResource, singular string) {
	return h.hook.ValidatingResource()
}

func (h validatingAdmissionHookWrapper) Admission(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse {
	return h.hook.Validate(admissionSpec)
}
