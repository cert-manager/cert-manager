package v1alpha1

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (i *IssuerStatus) ACMEStatus() *ACMEIssuerStatus {
	// this is an edge case, but this will prevent panics
	if i == nil {
		return &ACMEIssuerStatus{}
	}
	if i.ACME == nil {
		i.ACME = &ACMEIssuerStatus{}
	}
	return i.ACME
}

func (a *ACMEIssuerDNS01Config) Provider(name string) (*ACMEIssuerDNS01Provider, error) {
	if a == nil {
		return nil, fmt.Errorf("issuer does not contain DNS01 configuration for provider named %q", name)
	}
	for _, p := range a.Providers {
		if p.Name == name {
			return &(*&p), nil
		}
	}
	return nil, fmt.Errorf("issuer does not contain DNS01 configuration for provider named %q", name)
}

func ConfigForDomain(cfgs []DomainSolverConfig, domain string) *DomainSolverConfig {
	for _, cfg := range cfgs {
		for _, d := range cfg.Domains {
			if d == domain {
				return &cfg
			}
		}
	}
	return &DomainSolverConfig{}
}

func (c *CertificateStatus) ACMEStatus() *CertificateACMEStatus {
	// this is an edge case, but this will prevent panics
	if c == nil {
		return &CertificateACMEStatus{}
	}
	if c.ACME == nil {
		c.ACME = &CertificateACMEStatus{}
	}
	return c.ACME
}

func (iss *Issuer) HasCondition(condition IssuerCondition) bool {
	// this is an edge case, but this will prevent panics
	if iss == nil {
		return false
	}
	if len(iss.Status.Conditions) == 0 {
		return false
	}
	for _, cond := range iss.Status.Conditions {
		if condition.Type == cond.Type && condition.Status == cond.Status {
			return true
		}
	}
	return false
}

func (iss *Issuer) UpdateStatusCondition(conditionType IssuerConditionType, status ConditionStatus, reason, message string) {
	newCondition := IssuerCondition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	t := time.Now()

	if len(iss.Status.Conditions) == 0 {
		glog.Infof("Setting lastTransitionTime for Issuer %q condition %q to %v", iss.Name, conditionType, t)
		newCondition.LastTransitionTime = metav1.NewTime(t)
		iss.Status.Conditions = []IssuerCondition{newCondition}
	} else {
		for i, cond := range iss.Status.Conditions {
			if cond.Type == conditionType {
				if cond.Status != newCondition.Status {
					glog.Infof("Found status change for Issuer %q condition %q: %q -> %q; setting lastTransitionTime to %v", iss.Name, conditionType, cond.Status, status, t)
					newCondition.LastTransitionTime = metav1.NewTime(t)
				} else {
					newCondition.LastTransitionTime = cond.LastTransitionTime
				}

				iss.Status.Conditions[i] = newCondition
				break
			}
		}
	}
}

func (iss *ClusterIssuer) HasCondition(condition IssuerCondition) bool {
	// this is an edge case, but this will prevent panics
	if iss == nil {
		return false
	}
	if len(iss.Status.Conditions) == 0 {
		return false
	}
	for _, cond := range iss.Status.Conditions {
		if condition.Type == cond.Type && condition.Status == cond.Status {
			return true
		}
	}
	return false
}

func (iss *ClusterIssuer) UpdateStatusCondition(conditionType IssuerConditionType, status ConditionStatus, reason, message string) {
	newCondition := IssuerCondition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	t := time.Now()

	if len(iss.Status.Conditions) == 0 {
		glog.Infof("Setting lastTransitionTime for ClusterIssuer %q condition %q to %v", iss.Name, conditionType, t)
		newCondition.LastTransitionTime = metav1.NewTime(t)
		iss.Status.Conditions = []IssuerCondition{newCondition}
	} else {
		for i, cond := range iss.Status.Conditions {
			if cond.Type == conditionType {
				if cond.Status != newCondition.Status {
					glog.Infof("Found status change for ClusterIssuer %q condition %q: %q -> %q; setting lastTransitionTime to %v", iss.Name, conditionType, cond.Status, status, t)
					newCondition.LastTransitionTime = metav1.NewTime(t)
				} else {
					newCondition.LastTransitionTime = cond.LastTransitionTime
				}

				iss.Status.Conditions[i] = newCondition
				break
			}
		}
	}
}

func (crt *Certificate) HasCondition(condition CertificateCondition) bool {
	// this is an edge case, but this will prevent panics
	if crt == nil {
		return false
	}
	if len(crt.Status.Conditions) == 0 {
		return false
	}
	for _, cond := range crt.Status.Conditions {
		if condition.Type == cond.Type && condition.Status == cond.Status {
			return true
		}
	}
	return false
}

func (crt *Certificate) UpdateStatusCondition(conditionType CertificateConditionType, status ConditionStatus, reason, message string, forceTime bool) {
	newCondition := CertificateCondition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	t := time.Now()

	if len(crt.Status.Conditions) == 0 {
		glog.Infof("Setting lastTransitionTime for Certificate %q condition %q to %v", crt.Name, conditionType, t)
		newCondition.LastTransitionTime = metav1.NewTime(t)
		crt.Status.Conditions = []CertificateCondition{newCondition}
	} else {
		for i, cond := range crt.Status.Conditions {
			if cond.Type == conditionType {
				if cond.Status != newCondition.Status || forceTime {
					glog.Infof("Found status change for Certificate %q condition %q: %q -> %q; setting lastTransitionTime to %v", crt.Name, conditionType, cond.Status, status, t)
					newCondition.LastTransitionTime = metav1.NewTime(t)
				} else {
					newCondition.LastTransitionTime = cond.LastTransitionTime
				}

				crt.Status.Conditions[i] = newCondition
				return
			}
		}

		crt.Status.Conditions = append(crt.Status.Conditions, newCondition)
	}
}

type GenericIssuer interface {
	runtime.Object
	GetObjectMeta() *metav1.ObjectMeta
	GetSpec() *IssuerSpec
	GetStatus() *IssuerStatus
	UpdateStatusCondition(conditionType IssuerConditionType, status ConditionStatus, reason, message string)
	HasCondition(condition IssuerCondition) bool
	Copy() GenericIssuer
}

var _ GenericIssuer = &Issuer{}
var _ GenericIssuer = &ClusterIssuer{}

func (c *ClusterIssuer) GetObjectMeta() *metav1.ObjectMeta {
	return &c.ObjectMeta
}
func (c *ClusterIssuer) GetSpec() *IssuerSpec {
	return &c.Spec
}
func (c *ClusterIssuer) GetStatus() *IssuerStatus {
	return &c.Status
}
func (c *ClusterIssuer) SetSpec(spec IssuerSpec) {
	c.Spec = spec
}
func (c *ClusterIssuer) SetStatus(status IssuerStatus) {
	c.Status = status
}
func (c *ClusterIssuer) Copy() GenericIssuer {
	return c.DeepCopy()
}
func (c *Issuer) GetObjectMeta() *metav1.ObjectMeta {
	return &c.ObjectMeta
}
func (c *Issuer) GetSpec() *IssuerSpec {
	return &c.Spec
}
func (c *Issuer) GetStatus() *IssuerStatus {
	return &c.Status
}
func (c *Issuer) SetSpec(spec IssuerSpec) {
	c.Spec = spec
}
func (c *Issuer) SetStatus(status IssuerStatus) {
	c.Status = status
}
func (c *Issuer) Copy() GenericIssuer {
	return c.DeepCopy()
}
