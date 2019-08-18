package install

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/apitesting/roundtrip"

	cmfuzzer "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/fuzzer"
)

func TestRoundTripTypes(t *testing.T) {
	roundtrip.RoundTripTestForAPIGroup(t, Install, cmfuzzer.Funcs)
}
