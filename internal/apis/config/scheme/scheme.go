package scheme

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/jetstack/cert-manager/internal/apis/config"
	configv1alpha1 "github.com/jetstack/cert-manager/internal/apis/config/v1alpha1"
)

// NewSchemeAndCodecs is a utility function that returns a Scheme and CodecFactory
// that understand the types in the config.cert-manager.io API group. Passing mutators allows
// for adjusting the behavior of the CodecFactory, for example enable strict decoding.
func NewSchemeAndCodecs(mutators ...serializer.CodecFactoryOptionsMutator) (*runtime.Scheme, *serializer.CodecFactory, error) {
	scheme := runtime.NewScheme()
	if err := config.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}
	if err := configv1alpha1.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}
	codecs := serializer.NewCodecFactory(scheme, mutators...)
	return scheme, &codecs, nil
}
