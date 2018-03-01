package certificates

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type recorder struct {
	eventType string
	reason    string
	message   string
}

func (r *recorder) Event(object runtime.Object, eventtype, reason, message string) {
	r.eventType = eventtype
	r.reason = reason
	r.message = message
}

func (r *recorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	r.eventType = eventtype
	r.reason = reason
	r.message = messageFmt
}

func (r *recorder) PastEventf(object runtime.Object, timestamp metav1.Time, eventtype, reason, messageFmt string, args ...interface{}) {
	r.eventType = eventtype
	r.reason = reason
	r.message = messageFmt
}

func TestCalculateTimeBeforeExpiry(t *testing.T) {
	c := &Controller{}

	currentTime := time.Now()
	now = func() time.Time { return currentTime }
	defer func() { now = time.Now }()

	tests := []struct {
		desc           string
		notBefore      time.Time
		notAfter       time.Time
		duration       time.Duration
		renewBefore    time.Duration
		expectedExpiry time.Duration
		expectedReason string
	}{
		{
			desc:           "generate an event if certificate duration is lower than requested duration",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 90),
			duration:       time.Hour * 24 * 120,
			renewBefore:    0,
			expectedExpiry: time.Hour * 24 * 60,
			expectedReason: infoCertificateDuration,
		},
		{
			desc:           "default expiry to 30 days",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 120),
			duration:       0,
			renewBefore:    0,
			expectedExpiry: (time.Hour * 24 * 120) - (time.Hour * 24 * 30),
		},
		{
			desc:           "default expiry to 2/3 of total duration if duration < 30 days",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 20),
			duration:       0,
			renewBefore:    0,
			expectedExpiry: time.Hour * 24 * 20 * 2 / 3,
			expectedReason: infoScheduleModified,
		},
		{
			desc:           "expiry of 2/3 of certificate duration when duration < 30 minutes",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour),
			duration:       time.Hour,
			renewBefore:    time.Hour / 3,
			expectedExpiry: time.Hour * 2 / 3,
		},
		{
			desc:           "expiry of 60 days of certificate duration",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 365),
			duration:       time.Hour * 24 * 365,
			renewBefore:    time.Hour * 24 * 60,
			expectedExpiry: (time.Hour * 24 * 365) - (time.Hour * 24 * 60),
		},
		{
			desc:           "expiry of 2/3 of certificate duration when renewBefore greater than certificate duration",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 35),
			duration:       time.Hour * 24 * 35,
			renewBefore:    time.Hour * 24 * 40,
			expectedExpiry: time.Hour * 24 * 35 * 2 / 3,
			expectedReason: infoScheduleModified,
		},
	}

	for k, v := range tests {
		cert := &v1alpha1.Certificate{}
		x509Cert := &x509.Certificate{NotBefore: v.notBefore, NotAfter: v.notAfter}
		issuer := &v1alpha1.Issuer{}
		issuer.GetSpec().Duration = metav1.Duration{v.duration}
		issuer.GetSpec().RenewBefore = metav1.Duration{v.renewBefore}

		rec := &recorder{}
		c.recorder = rec

		duration := c.calculateTimeBeforeExpiry(x509Cert, cert, issuer)
		if duration != v.expectedExpiry {
			t.Errorf("test # %d - %s: got %v, expected %v", k, v.desc, duration, v.expectedExpiry)
		}

		if rec.reason != v.expectedReason {
			t.Errorf("test # %d - %s: got %v, expected %v", k, v.desc, rec.reason, v.expectedReason)
		}
	}
}
