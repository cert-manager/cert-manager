/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubectl/pkg/describe"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/status/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

type CertificateStatus struct {
	// Name of the Certificate resource
	Name string
	// Namespace of the Certificate resource
	Namespace string
	// Creation Time of Certificate resource
	CreationTime metav1.Time
	// Conditions of Certificate resource
	Conditions []cmapi.CertificateCondition
	// DNS Names of Certificate resource
	DNSNames []string
	// Events of Certificate resource
	Events *v1.EventList
	// Not Before of Certificate resource
	NotBefore *metav1.Time
	// Not After of Certificate resource
	NotAfter *metav1.Time
	// Renewal Time of Certificate resource
	RenewalTime *metav1.Time

	IssuerStatus *IssuerStatus

	SecretStatus *SecretStatus

	CRStatus *CRStatus

	OrderStatus *OrderStatus

	ChallengeStatusList *ChallengeStatusList
}

type IssuerStatus struct {
	// If Error is not nil, there was a problem getting the status of the Issuer/ClusterIssuer resource,
	// so the rest of the fields is unusable
	Error error
	// Name of the Issuer/ClusterIssuer resource
	Name string
	// Kind of the resource, can be Issuer or ClusterIssuer
	Kind string
	// Conditions of Issuer/ClusterIssuer resource
	Conditions []cmapi.IssuerCondition
	// Events of Issuer/ClusterIssuer resource
	Events *v1.EventList
}

type SecretStatus struct {
	// If Error is not nil, there was a problem getting the status of the Secret resource,
	// so the rest of the fields is unusable
	Error error
	// Name of the Secret resource
	Name string
	// Issuer Countries of the x509 certificate in the Secret
	IssuerCountry []string
	// Issuer Organisations of the x509 certificate in the Secret
	IssuerOrganisation []string
	// Issuer Common Name of the x509 certificate in the Secret
	IssuerCommonName string
	// Key Usage of the x509 certificate in the Secret
	KeyUsage x509.KeyUsage
	// Extended Key Usage of the x509 certificate in the Secret
	ExtKeyUsage []x509.ExtKeyUsage
	// Public Key Algorithm of the x509 certificate in the Secret
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	// Signature Algorithm of the x509 certificate in the Secret
	SignatureAlgorithm x509.SignatureAlgorithm
	// Subject Key Id of the x509 certificate in the Secret
	SubjectKeyId []byte
	// Authority Key Id of the x509 certificate in the Secret
	AuthorityKeyId []byte
	// Serial Number of the x509 certificate in the Secret
	SerialNumber *big.Int
	// Events of Secret resource
	Events *v1.EventList
}

type CRStatus struct {
	// If Error is not nil, there was a problem getting the status of the CertificateRequest resource,
	// so the rest of the fields is unusable
	Error error
	// Name of the CertificateRequest resource
	Name string
	// Namespace of the CertificateRequest resource
	Namespace string
	// Conditions of CertificateRequest resource
	Conditions []cmapi.CertificateRequestCondition
	// Events of CertificateRequest resource
	Events *v1.EventList
}

type OrderStatus struct {
	// If Error is not nil, there was a problem getting the status of the Order resource,
	// so the rest of the fields is unusable
	Error error
	// Name of the Order resource
	Name string
	// State of Order resource
	State cmacme.State
	// Reason why the Order resource is in its State
	Reason string
	// What authorizations must be completed to validate the DNS names specified on the Order
	Authorizations []cmacme.ACMEAuthorization
	// Time the Order failed
	FailureTime *metav1.Time
}

type ChallengeStatusList struct {
	// If Error is not nil, there was a problem getting the status of the Order resource,
	// so the rest of the fields is unusable
	Error             error
	ChallengeStatuses []*ChallengeStatus
}

type ChallengeStatus struct {
	Name       string
	Type       cmacme.ACMEChallengeType
	Token      string
	Key        string
	State      cmacme.State
	Reason     string
	Processing bool
	Presented  bool
}

func newCertificateStatusFromCert(crt *cmapi.Certificate) *CertificateStatus {
	if crt == nil {
		return nil
	}
	return &CertificateStatus{
		Name: crt.Name, Namespace: crt.Namespace, CreationTime: crt.CreationTimestamp,
		Conditions: crt.Status.Conditions, DNSNames: crt.Spec.DNSNames,
		NotBefore: crt.Status.NotBefore, NotAfter: crt.Status.NotAfter, RenewalTime: crt.Status.RenewalTime}
}

func (status *CertificateStatus) withEvents(events *v1.EventList) *CertificateStatus {
	status.Events = events
	return status
}

func (status *CertificateStatus) withGenericIssuer(genericIssuer cmapi.GenericIssuer, issuerKind string, issuerEvents *v1.EventList, err error) *CertificateStatus {
	if err != nil {
		status.IssuerStatus = &IssuerStatus{Error: err}
		return status
	}
	if genericIssuer == nil {
		return status
	}
	if issuerKind == "ClusterIssuer" {
		status.IssuerStatus = &IssuerStatus{Name: genericIssuer.GetName(), Kind: "ClusterIssuer",
			Conditions: genericIssuer.GetStatus().Conditions, Events: issuerEvents}
		return status
	}
	status.IssuerStatus = &IssuerStatus{Name: genericIssuer.GetName(), Kind: "Issuer",
		Conditions: genericIssuer.GetStatus().Conditions, Events: issuerEvents}
	return status
}

func (status *CertificateStatus) withSecret(secret *v1.Secret, secretEvents *v1.EventList, err error) *CertificateStatus {
	if err != nil {
		status.SecretStatus = &SecretStatus{Error: err}
		return status
	}
	if secret == nil {
		return status
	}
	certData := secret.Data["tls.crt"]

	if len(certData) == 0 {
		status.SecretStatus = &SecretStatus{Error: fmt.Errorf("error: 'tls.crt' of Secret %q is not set\n", secret.Name)}
		return status
	}

	x509Cert, err := pki.DecodeX509CertificateBytes(certData)
	if err != nil {
		status.SecretStatus = &SecretStatus{Error: fmt.Errorf("error when parsing 'tls.crt' of Secret %q: %s\n", secret.Name, err)}
		return status
	}

	status.SecretStatus = &SecretStatus{Error: nil, Name: secret.Name, IssuerCountry: x509Cert.Issuer.Country,
		IssuerOrganisation: x509Cert.Issuer.Organization,
		IssuerCommonName:   x509Cert.Issuer.CommonName, KeyUsage: x509Cert.KeyUsage,
		ExtKeyUsage: x509Cert.ExtKeyUsage, PublicKeyAlgorithm: x509Cert.PublicKeyAlgorithm,
		SignatureAlgorithm: x509Cert.SignatureAlgorithm,
		SubjectKeyId:       x509Cert.SubjectKeyId, AuthorityKeyId: x509Cert.AuthorityKeyId,
		SerialNumber: x509Cert.SerialNumber, Events: secretEvents}
	return status
}

func (status *CertificateStatus) withCR(req *cmapi.CertificateRequest, events *v1.EventList, err error) *CertificateStatus {
	if err != nil {
		status.CRStatus = &CRStatus{Error: err}
		return status
	}
	if req == nil {
		return status
	}
	status.CRStatus = &CRStatus{Name: req.Name, Namespace: req.Namespace, Conditions: req.Status.Conditions, Events: events}
	return status
}

func (status *CertificateStatus) withOrder(order *cmacme.Order, err error) *CertificateStatus {
	if err != nil {
		status.OrderStatus = &OrderStatus{Error: err}
		return status
	}
	if order == nil {
		return status
	}

	status.OrderStatus = &OrderStatus{Name: order.Name, State: order.Status.State,
		Reason: order.Status.Reason, Authorizations: order.Status.Authorizations,
		FailureTime: order.Status.FailureTime}
	return status
}

func (status *CertificateStatus) withChallenges(challenges []*cmacme.Challenge, err error) *CertificateStatus {
	if err != nil {
		status.ChallengeStatusList = &ChallengeStatusList{Error: err}
		return status
	}
	if len(challenges) == 0 {
		return status
	}

	var list []*ChallengeStatus
	for _, challenge := range challenges {
		list = append(list, &ChallengeStatus{
			Name:       challenge.Name,
			Type:       challenge.Spec.Type,
			Token:      challenge.Spec.Token,
			Key:        challenge.Spec.Key,
			State:      challenge.Status.State,
			Reason:     challenge.Status.Reason,
			Processing: challenge.Status.Processing,
			Presented:  challenge.Status.Presented,
		})
	}
	status.ChallengeStatusList = &ChallengeStatusList{ChallengeStatuses: list}
	return status
}

func (status *CertificateStatus) String() string {
	output := ""
	output += fmt.Sprintf("Name: %s\n", status.Name)
	output += fmt.Sprintf("Namespace: %s\n", status.Namespace)
	output += fmt.Sprintf("Created at: %s\n", formatTimeString(&status.CreationTime))

	// Output one line about each type of Condition that is set.
	// Certificate can have multiple Conditions of different types set, e.g. "Ready" or "Issuing"
	conditionMsg := ""
	for _, con := range status.Conditions {
		conditionMsg += fmt.Sprintf("  %s: %s, Reason: %s, Message: %s\n", con.Type, con.Status, con.Reason, con.Message)
	}
	if conditionMsg == "" {
		conditionMsg = "  No Conditions set\n"
	}
	output += fmt.Sprintf("Conditions:\n%s", conditionMsg)

	output += fmt.Sprintf("DNS Names:\n%s", formatStringSlice(status.DNSNames))

	output += eventsToString(status.Events, 0)

	output += status.IssuerStatus.String()
	output += status.SecretStatus.String()

	output += fmt.Sprintf("Not Before: %s\n", formatTimeString(status.NotBefore))
	output += fmt.Sprintf("Not After: %s\n", formatTimeString(status.NotAfter))
	output += fmt.Sprintf("Renewal Time: %s\n", formatTimeString(status.RenewalTime))

	output += status.CRStatus.String()

	// OrderStatus is nil is not found or Issuer/ClusterIssuer is not ACME Issuer
	if status.OrderStatus != nil {
		output += status.OrderStatus.String()
	}

	if status.ChallengeStatusList != nil {
		output += status.ChallengeStatusList.String()
	}

	return output
}

// String returns the information about the status of a Issuer/ClusterIssuer as a string to be printed as output
func (issuerStatus *IssuerStatus) String() string {
	if issuerStatus.Error != nil {
		return issuerStatus.Error.Error()
	}

	issuerFormat := `Issuer:
  Name: %s
  Kind: %s
  Conditions:
  %s`
	conditionMsg := ""
	for _, con := range issuerStatus.Conditions {
		conditionMsg += fmt.Sprintf("  %s: %s, Reason: %s, Message: %s\n", con.Type, con.Status, con.Reason, con.Message)
	}
	if conditionMsg == "" {
		conditionMsg = "  No Conditions set\n"
	}
	output := fmt.Sprintf(issuerFormat, issuerStatus.Name, issuerStatus.Kind, conditionMsg)
	output += eventsToString(issuerStatus.Events, 1)
	return output
}

// String returns the information about the status of a Secret as a string to be printed as output
func (secretStatus *SecretStatus) String() string {
	if secretStatus.Error != nil {
		return secretStatus.Error.Error()
	}

	secretFormat := `Secret:
  Name: %s
  Issuer Country: %s
  Issuer Organisation: %s
  Issuer Common Name: %s
  Key Usage: %s
  Extended Key Usages: %s
  Public Key Algorithm: %s
  Signature Algorithm: %s
  Subject Key ID: %s
  Authority Key ID: %s
  Serial Number: %s
`

	extKeyUsageString, err := extKeyUsageToString(secretStatus.ExtKeyUsage)
	if err != nil {
		extKeyUsageString = err.Error()
	}
	output := fmt.Sprintf(secretFormat, secretStatus.Name, strings.Join(secretStatus.IssuerCountry, ", "),
		strings.Join(secretStatus.IssuerOrganisation, ", "),
		secretStatus.IssuerCommonName, keyUsageToString(secretStatus.KeyUsage),
		extKeyUsageString, secretStatus.PublicKeyAlgorithm, secretStatus.SignatureAlgorithm,
		hex.EncodeToString(secretStatus.SubjectKeyId), hex.EncodeToString(secretStatus.AuthorityKeyId),
		hex.EncodeToString(secretStatus.SerialNumber.Bytes()))
	output += eventsToString(secretStatus.Events, 1)
	return output
}

var (
	keyUsageToStringMap = map[int]string{
		1:   "Digital Signature",
		2:   "Content Commitment",
		4:   "Key Encipherment",
		8:   "Data Encipherment",
		16:  "Key Agreement",
		32:  "Cert Sign",
		64:  "CRL Sign",
		128: "Encipher Only",
		256: "Decipher Only",
	}
	keyUsagePossibleValues  = []int{256, 128, 64, 32, 16, 8, 4, 2, 1}
	extKeyUsageStringValues = []string{"Any", "Server Authentication", "Client Authentication", "Code Signing", "Email Protection",
		"IPSEC End System", "IPSEC Tunnel", "IPSEC User", "Time Stamping", "OCSP Signing", "Microsoft Server Gated Crypto",
		"Netscape Server Gated Crypto", "Microsoft Commercial Code Signing", "Microsoft Kernel Code Signing",
	}
)

func keyUsageToString(usage x509.KeyUsage) string {
	usageInt := int(usage)
	var usageStrings []string
	for _, val := range keyUsagePossibleValues {
		if usageInt >= val {
			usageInt -= val
			usageStrings = append(usageStrings, keyUsageToStringMap[val])
		}
		if usageInt == 0 {
			break
		}
	}
	// Reversing because that's usually the order the usages are printed
	for i := 0; i < len(usageStrings)/2; i++ {
		opp := len(usageStrings) - 1 - i
		usageStrings[i], usageStrings[opp] = usageStrings[opp], usageStrings[i]
	}
	return strings.Join(usageStrings, ", ")
}

func extKeyUsageToString(extUsages []x509.ExtKeyUsage) (string, error) {
	var extUsageStrings []string
	for _, extUsage := range extUsages {
		if extUsage < 0 || int(extUsage) >= len(extKeyUsageStringValues) {
			return "", fmt.Errorf("error when converting Extended Usages to string: encountered unknown Extended Usage with code %d", extUsage)
		}
		extUsageStrings = append(extUsageStrings, extKeyUsageStringValues[extUsage])
	}
	return strings.Join(extUsageStrings, ", "), nil
}

// String returns the information about the status of a CR as a string to be printed as output
func (crStatus *CRStatus) String() string {
	if crStatus.Error != nil {
		return crStatus.Error.Error()
	}

	crFormat := `
  Name: %s
  Namespace: %s
  Conditions:
  %s`
	conditionMsg := ""
	for _, con := range crStatus.Conditions {
		conditionMsg += fmt.Sprintf("  %s: %s, Reason: %s, Message: %s\n", con.Type, con.Status, con.Reason, con.Message)
	}
	if conditionMsg == "" {
		conditionMsg = "  No Conditions set\n"
	}
	infos := fmt.Sprintf(crFormat, crStatus.Name, crStatus.Namespace, conditionMsg)
	infos = fmt.Sprintf("CertificateRequest:%s", infos)

	infos += eventsToString(crStatus.Events, 1)
	return infos
}

// String returns the information about the status of a CR as a string to be printed as output
func (orderStatus *OrderStatus) String() string {
	if orderStatus.Error != nil {
		return orderStatus.Error.Error()
	}

	output := "Order:\n"
	output += fmt.Sprintf("  Name: %s\n", orderStatus.Name)
	output += fmt.Sprintf("  State: %s, Reason: %s\n", orderStatus.State, orderStatus.Reason)
	authString := ""
	for _, auth := range orderStatus.Authorizations {
		wildcardString := "nil (bool pointer not set)"
		if auth.Wildcard != nil {
			wildcardString = fmt.Sprintf("%t", *auth.Wildcard)
		}
		authString += fmt.Sprintf("    URL: %s, Identifier: %s, Initial State: %s, Wildcard: %s\n", auth.URL, auth.Identifier, auth.InitialState, wildcardString)
	}
	if authString == "" {
		output += "  No Authorizations for this Order\n"
	} else {
		output += "  Authorizations:\n"
		output += authString
	}
	if orderStatus.FailureTime != nil {
		output += fmt.Sprintf("  FailureTime: %s\n", formatTimeString(orderStatus.FailureTime))
	}

	return output
}

func (c *ChallengeStatusList) String() string {
	if c.Error != nil {
		return c.Error.Error()
	}

	challengeStrings := []string{}
	for _, challengeStatus := range c.ChallengeStatuses {
		challengeStrings = append(challengeStrings, challengeStatus.String())
	}
	output := "Challenges:\n"
	output += formatStringSlice(challengeStrings)
	return output
}

func (challengeStatus *ChallengeStatus) String() string {
	return fmt.Sprintf("Name: %s, Type: %s, Token: %s, Key: %s, State: %s, Reason: %s, Processing: %t, Presented: %t",
		challengeStatus.Name, challengeStatus.Type, challengeStatus.Token, challengeStatus.Key, challengeStatus.State,
		challengeStatus.Reason, challengeStatus.Processing, challengeStatus.Presented)
}

func eventsToString(events *v1.EventList, baseLevel int) string {
	var buf bytes.Buffer
	defer buf.Reset()
	tabWriter := util.NewTabWriter(&buf)
	prefixWriter := describe.NewPrefixWriter(tabWriter)
	util.DescribeEvents(events, prefixWriter, baseLevel)
	tabWriter.Flush()
	return buf.String()
}
