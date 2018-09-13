package issuer

import (
	"fmt"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func ValidateDuration(issuer v1alpha1.GenericIssuer) error {
	duration := issuer.GetSpec().Duration.Duration
	if duration == 0 {
		duration = v1alpha1.DefaultCertificateDuration
	}
	renewBefore := issuer.GetSpec().RenewBefore.Duration
	if renewBefore == 0 {
		renewBefore = v1alpha1.DefaultRenewBefore
	}
	if duration <= v1alpha1.MinimumCertificateDuration {
		return fmt.Errorf("certificate duration must be greater than %s", v1alpha1.MinimumCertificateDuration)
	}
	if renewBefore < v1alpha1.MinimumRenewBefore {
		return fmt.Errorf("certificate renewBefore %s value must be greater than %s", renewBefore, v1alpha1.MinimumRenewBefore)
	}
	if duration <= renewBefore {
		return fmt.Errorf("certificate duration %s must be greater than renewBefore %s ", duration, renewBefore)
	}
	return nil
}
