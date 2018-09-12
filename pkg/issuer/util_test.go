
package issuer
 import (
	"testing"
	"time"
 	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)
 const (
	success = iota
	fail
)
 func TestValidateDuration(t *testing.T) {
	cases := []struct {
		inputDuration    time.Duration
		inputRenewBefore time.Duration
		expected         int
		label            string
	}{
		{
			inputDuration:    0,
			inputRenewBefore: time.Hour * 24 * 365 * 10,
			expected:         fail,
			label:            "renewBefore is bigger than the default duration",
		},
		{
			inputDuration:    time.Hour * 24 * 30,
			inputRenewBefore: time.Hour * 24 * 35,
			expected:         fail,
			label:            "renewBefore is bigger than the duration",
		},
		{
			inputDuration:    0,
			inputRenewBefore: time.Second,
			expected:         fail,
			label:            "renewBefore is less than the minimum permitted value",
		},
		{
			inputDuration:    time.Second,
			inputRenewBefore: 0,
			expected:         fail,
			label:            "duration is less than the minimum permitted value",
		},
		{
			inputDuration:    0,
			inputRenewBefore: 0,
			expected:         success,
			label:            "default duration and renewBefore should be valid",
		},
	}
 	issuer := &v1alpha1.Issuer{}
	for _, v := range cases {
		issuer.Spec.Duration = metav1.Duration{v.inputDuration}
		issuer.Spec.RenewBefore = metav1.Duration{v.inputRenewBefore}
 		err := ValidateDuration(issuer)
		if err == nil && v.expected == fail {
			t.Errorf(v.label)
		}
		if err != nil && v.expected == success {
			t.Errorf(v.label)
		}
	}
}