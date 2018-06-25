package validation

import (
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Validation functions for cert-manager v1alpha1 ClusterIssuer types

func ValidateClusterIssuer(iss *v1alpha1.ClusterIssuer) field.ErrorList {
	allErrs := ValidateIssuerSpec(&iss.Spec, field.NewPath("spec"))
	return allErrs
}
