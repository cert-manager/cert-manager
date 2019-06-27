package internal

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// Security policies documentation:
// https://source.datanerd.us/agents/agent-specs/blob/master/Language-Agent-Security-Policies.md

// SecurityPolicies contains the security policies.
type SecurityPolicies struct {
	RecordSQL                 securityPolicy `json:"record_sql"`
	AttributesInclude         securityPolicy `json:"attributes_include"`
	AllowRawExceptionMessages securityPolicy `json:"allow_raw_exception_messages"`
	CustomEvents              securityPolicy `json:"custom_events"`
	CustomParameters          securityPolicy `json:"custom_parameters"`
}

// PointerIfPopulated returns a reference to the security policies if they have
// been populated from JSON.
func (sp *SecurityPolicies) PointerIfPopulated() *SecurityPolicies {
	emptyPolicies := SecurityPolicies{}
	if nil != sp && *sp != emptyPolicies {
		return sp
	}
	return nil
}

type securityPolicy struct {
	EnabledVal *bool `json:"enabled"`
}

func (p *securityPolicy) Enabled() bool           { return nil == p.EnabledVal || *p.EnabledVal }
func (p *securityPolicy) SetEnabled(enabled bool) { p.EnabledVal = &enabled }
func (p *securityPolicy) IsSet() bool             { return nil != p.EnabledVal }

type policyer interface {
	SetEnabled(bool)
	IsSet() bool
}

// UnmarshalJSON decodes security policies sent from the preconnect endpoint.
func (sp *SecurityPolicies) UnmarshalJSON(data []byte) (er error) {
	defer func() {
		// Zero out all fields if there is an error to ensure that the
		// populated check works.
		if er != nil {
			*sp = SecurityPolicies{}
		}
	}()

	var raw map[string]struct {
		Enabled  bool `json:"enabled"`
		Required bool `json:"required"`
	}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return fmt.Errorf("unable to unmarshal security policies: %v", err)
	}

	knownPolicies := make(map[string]policyer)

	spv := reflect.ValueOf(sp).Elem()
	for i := 0; i < spv.NumField(); i++ {
		fieldAddress := spv.Field(i).Addr()
		field := fieldAddress.Interface().(policyer)
		name := spv.Type().Field(i).Tag.Get("json")
		knownPolicies[name] = field
	}

	for name, policy := range raw {
		p, ok := knownPolicies[name]
		if !ok {
			if policy.Required {
				return errUnknownRequiredPolicy{name: name}
			}
		} else {
			p.SetEnabled(policy.Enabled)
		}
	}
	for name, policy := range knownPolicies {
		if !policy.IsSet() {
			return errUnsetPolicy{name: name}
		}
	}
	return nil
}

type errUnknownRequiredPolicy struct{ name string }

func (err errUnknownRequiredPolicy) Error() string {
	return fmt.Sprintf("policy '%s' is unrecognized, please check for a newer agent version or contact support", err.name)
}

type errUnsetPolicy struct{ name string }

func (err errUnsetPolicy) Error() string {
	return fmt.Sprintf("policy '%s' not received, please contact support", err.name)
}

func isDisconnectSecurityPolicyError(e error) bool {
	if _, ok := e.(errUnknownRequiredPolicy); ok {
		return true
	}
	if _, ok := e.(errUnsetPolicy); ok {
		return true
	}
	return false
}
