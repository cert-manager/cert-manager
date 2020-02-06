package api

import (
	"github.com/Venafi/vcert/pkg/certificate"
)

// CustomField defines a custom field to be passed to Venafi
type CustomField struct {
	Type  certificate.CustomFieldType `json:"type,omitempty"`
	Name  string                      `json:"name"`
	Value string                      `json:"value"`
}
