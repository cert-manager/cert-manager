# ACME Order & Challenge CRDs to handle Order flow

This is a proposal that discusses a way to improve the ACME order handling flow
to address recent issues we've had with the existing implementation.

## Problem

The current ACME order handling process is opaque and difficult to debug.
The majority of the logic is encoded into the ACME issuer's `Prepare` function,
which has become bloated.

This, combined with the asynchronous nature of the controllers design, has made
it difficult to reason about and test the ACME order flow.

It has also made it difficult to control the number of API requests made to ACME
servers, as there are many other failure modes to consider within this Prepare
function meaning bugs leading to tight loops are easy to introduce, and
difficult to find.

## Proposed solution

We will add two new resource types (CRDs), `Order` and `Challenge` in order to
mirror their counterpart resource types in the ACME server.

The `spec` fields of these two resources will be **immutable** - that is, changes
to `spec` fields will not be allowed after the resource is initially created.

This allows us to more clearly reason about and know when a new order or
challenge is created.

These two resources are **not intended to be created by users**. Rather, the
ACME issuer will be modified to manage and monitor the lifecycle of Order
resources in an attempt to obtain a valid TLS certificate as requested by the
user with a Certificate resource, as is already today.
The new Orders controller will then create and monitor Challenge resources to
fulfil the ACME authorizations needed to complete the Order.

## Required changes

Numerous changes will need to be made across the codebase to accommodate this.

### API changes

#### New types

##### Order

```go

// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// +kubebuilder:resource:path=orders
type Order struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   OrderSpec   `json:"spec"`
	Status OrderStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OrderList is a list of Orders
type OrderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Order `json:"items"`
}

type OrderSpec struct {
	// Certificate signing request bytes in DER encoding.
	// This will be used when finalizing the order.
	// This field must be set on the order.
	CSR []byte `json:"csr"`

	// IssuerRef references a properly configured ACME-type Issuer which should
	// be used to create this Order.
	// If the Issuer does not exist, processing will be retried.
	// If the Issuer is not an 'ACME' Issuer, an error will be returned and the
	// Order will be marked as failed.
	IssuerRef ObjectReference `json:"issuerRef"`

	// CommonName is the common name as specified on the DER encoded CSR.
	// If CommonName is not specified, the first DNSName specified will be used
	// as the CommonName.
	// At least on of CommonName or a DNSName must be set.
	// This field must match the corresponding field on the DER encoded CSR.
	CommonName string `json:"commonName,omitempty"`

	// DNSNames is a list of DNS names that should be included as part of the Order
	// validation process.
	// If CommonName is not specified, the first DNSName specified will be used
	// as the CommonName.
	// At least on of CommonName or a DNSName must be set.
	// This field must match the corresponding field on the DER encoded CSR.
	DNSNames []string `json:"dnsNames,omitempty"`

	// Config specifies a mapping from DNS identifiers to how those identifiers
	// should be solved when performing ACME challenges.
	// A config entry must exist for each domain listed in DNSNames and CommonName.
	Config []DomainSolverConfig `json:"config"`
}

type OrderStatus struct {
	// URL of the Order.
	// This will initially be empty when the resource is first created.
	// The Order controller will populate this field when the Order is first processed.
	// This field will be immutable after it is initially set.
	URL string `json:"url"`

	// FinalizeURL of the Order.
	// This is used to obtain certificates for this order once it has been completed.
	FinalizeURL string `json:"finalizeURL"`

	// Certificate is a copy of the PEM encoded certificate for this Order.
	// This field will be populated after the order has been successfully
	// finalized with the ACME server, and the order has transitioned to the
	// 'valid' state.
	Certificate []byte `json:"certificate"`

	// State contains the current state of this Order resource.
	// States 'success' and 'expired' are 'final'
	State State `json:"state"`

	// Reason optionally provides more information about a why the order is in
	// the current state.
	Reason string `json:"reason"`

	// Challenges is a list of ChallengeSpecs for Challenges that must be created
	// in order to complete this Order.
	Challenges []ChallengeSpec `json:"challenges,omitempty"`

	// FailureTime stores the time that this order failed.
	// This is used to influence garbage collection and back-off.
	FailureTime *metav1.Time `json:"failureTime,omitempty"`
}

// State represents the state of an ACME resource, such as an Order.
// The possible options here map to the corresponding values in the
// ACME specification.
// Full details of these values can be found there.
// Clients utilising this type **must** also gracefully handle unknown
// values, as the contents of this enumeration may be added to over time.
type State string

const (
	// Unknown is not a real state as part of the ACME spec.
	// It is used to represent an unrecognised value.
	Unknown State = ""

	// Valid signifies that an ACME resource is in a valid state.
	// If an Order is marked 'valid', all validations on that Order
	// have been completed successfully.
	// This is a transient state as of ACME draft-12
	Valid State = "valid"

	// Ready signifies that an ACME resource is in a ready state.
	// If an Order is marked 'Ready', the corresponding certificate
	// is ready and can be obtained.
	// This is a final state.
	Ready State = "ready"

	// Pending signifies that an ACME resource is still pending and is not yet ready.
	// If an Order is marked 'Pending', the validations for that Order are still in progress.
	// This is a transient state.
	Pending State = "pending"

	// Processing signifies that an ACME resource is being processed by the server.
	// If an Order is marked 'Processing', the validations for that Order are currently being processed.
	// This is a transient state.
	Processing State = "processing"

	// Invalid signifies that an ACME resource is invalid for some reason.
	// If an Order is marked 'invalid', one of its validations must be invalid for some reason.
	// This is a final state.
	Invalid State = "invalid"

	// Expired signifies that an ACME resource has expired.
	// If an Order is marked 'Expired', one of its validations may have expired or the Order itself.
	// This is a final state.
    Expired State = "expired"

	// Errored signifies that the ACME resource has errored for some reason.
	// This is a catch-all state, and is used for marking internal cert-manager
	// errors such as validation failures.
	// 'Errored' is treated similarly to 'Invalid', in that failing Order's will
	// be tried after a period of time has passed since failure.
	// This is a final state.
	Errored State = "errored"
)
```

##### Challenge

```go
// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// +kubebuilder:resource:path=challenges
type Challenge struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   ChallengeSpec   `json:"spec"`
	Status ChallengeStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ChallengeList is a list of Challenges
type ChallengeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Challenge `json:"items"`
}

type ChallengeSpec struct {
	// AuthzURL is the URL to the ACME Authorization resource that this
	// challenge is a part of.
	AuthzURL string `json:"authzURL"`

	// Type is the type of ACME challenge this resource represents, e.g. "dns01"
	// or "http01"
	Type string `json:"type"`

	// URL is the URL of the ACME Challenge resource for this challenge.
	// This can be used to lookup details about the status of this challenge.
	URL string `json:"url"`

	// DNSName is the identifier that this challenge is for, e.g. example.com.
	DNSName string `json:"dnsName"`

	// Token is the ACME challenge token for this challenge.
	Token string `json:"token"`

	// Key is the ACME challenge key for this challenge
	Key string `json:"key"`

	// Wildcard will be true if this challenge is for a wildcard identifier,
	// for example '*.example.com'
	Wildcard bool `json:"wildcard"`

	// Config specifies the solver configuration for this challenge.
	Config SolverConfig `json:"config"`

	// IssuerRef references a properly configured ACME-type Issuer which should
	// be used to create this Challenge.
	// If the Issuer does not exist, processing will be retried.
	// If the Issuer is not an 'ACME' Issuer, an error will be returned and the
	// Challenge will be marked as failed.
	IssuerRef ObjectReference `json:"issuerRef"`
}

type ChallengeStatus struct {
	// Processing is used to denote whether this challenge should be processed
	// or not.
	// This field will only be set to true by the 'scheduling' component.
	// It will only be set to false by the 'challenges' controller, after the
	// challenge has reached a final state or timed out.
	// If this field is set to false, the challenge controller will not take
	// any more action.
	Processing bool `json:"processing"`

	// Presented will be set to true if the challenge values for this challenge
	// are currently 'presented'.
	// This *does not* imply the self check is passing. Only that the values
	// have been 'submitted' for the appropriate challenge mechanism (i.e. the
	// DNS01 TXT record has been presented, or the HTTP01 configuration has been
	// configured).
	Presented bool `json:"presented"`

	// Reason contains human readable information on why the Challenge is in the
	// current state.
	Reason string `json:"reason"`

	// State contains the current 'state' of the challenge.
	// If not set, the state of the challenge is unknown.
	State State `json:"state"`
}
```

#### Changes to existing types

The scope of changes to existing types as been purposely kept as small as possible.

We do however require a change to the `status` field of the Certificate resource
type. This should not be too problematic for users, as the cert-manager controller
should be able to tolerate this change seamlessly.

```go
// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
	Conditions      []CertificateCondition `json:"conditions,omitempty"`

	/////// REMOVED FIELD ///////
	// ACME            *CertificateACMEStatus `json:"acme,omitempty"`

	/////// NEW FIELD ///////
	LastFailureTime *metav1.Time           `json:"lastFailureTime,omitempty"`
}
```

### Controllers

Two new controllers will be built to reconcile the new `Order` and `Challenge`
types.

This two controllers will take the majority of the logic that used to exist in
the `Prepare` function of the ACME issuer.

#### ACME Issuer

The ACME issuer is modified to manage Order resources instead of actually
performing the ACME validation flow.

Each time the Issue function is called, the controller will check the state
of the Order resource that it has created on a previous invocation of the
Issue function, and if it is valid then return the Certificate as stored on
`order.status.certificate'. It will also verify that the Certificate stored on
that Order resource is 'up to date' (taking into account the Certificate's
configured `renewBefore`).

An Order resource remains even after the Certificate has been issued
successfully. This allows users to delete their Secret resource and have the
same certificate re-issued so long as that certificate is still within the
bounds of 'valid' (as dictated by the renewBefore field on the Certificate).
If a user wants to force a new Order (i.e. new x509 certificate), they should
delete the Order resource that exists for the Certificate.

If the Order for a Certificate fails, the ACME issuer will:

* Record the `certificate.status.lastFailureTime` as `time.Now()` if it is not
already set.

* Prevent creation of a new Order resource until 1h after the recorded `lastFailureTime`.

Just before retrying the Order, the old Order resource will be deleted to
ensure we don't accumulate too many Order & Challenge resources when an issuance
keeps failing.

#### Order controller

When an order is created, all of the spec fields must be defined, including CSR.
The Order controller will be responsible for handling the entirety of an ACME
order.
The 'spec' describes an order to be created. The controller will update the
'status' fields of the Order, sometimes by re-checking the order status with
the ACME server, throughout the Order handling flow.

* The Order controller will attempt to create a new order with the ACME server
if the `status.url` field is not set. It will copy details of the order, e.g.
the list of authorizations that must be completed, back onto the Order
resource's 'status' block, to save subsequent calls to the ACME server for this
information.

* If the order's state is 'final' (i.e. one of valid, invalid, expired, errored)
then the controller will take no further action and return. If the Order has
succeeded, it will delete all Challenge resources it has created for the Order.
If the Order fails for any reason, the Challenge resources will be retained
to allow users to debug the failures.

* For each authorization on the Order, the order controller will select a challenge
type to use to solve the authorization (based on the Issuer config and Order's
SolverConfig) and then ensure a Challenge resource for each authorization exists.

* The order controller will check the status of the Challenge resources that are
related to it, and once all of them are 'valid', will resync the Order state
with the ACME server to confirm it has entered the 'Ready' state.

* If the order is 'ready', the order controller will attempt to 'finalize' the
order using the CSR as specified on the Order resource (i.e. `spec.csr`).
After this finalization has completed, the order status will be updated and the
order's `status.certificate` field will be set to the encoded PEM certificate
data.

* If the order is 'invalid' (or any other failed state), the order controller
will take no further action - this prevents additional ACME API calls, and
allows users to debug failures easily. It also enables predictable retries of
Orders, as a single Order resource represents a single ACME order.

In its current implementation, it is unlikely that cert-manager will observe
an Order transitioning into an 'expired' or 'revoked' state.

This is because once an Order enters a 'valid' or 'invalid' state, its status
will no longer be synced with the ACME server. This should not cause an issue
as once a certificate is nearing expiry, we will force a new order to be
created anyway.

We may need to consider mechanisms for periodically updating the Order's state
in future, but such an implementation would require special consideration to
ensure we don't query the ACME API too aggressively.

#### Challenge controller

The challenge controller is responsible for:

* presenting challenges using a configured solver (i.e. a dns01 provider, or by
creating resources in order to solve http01 challenges).

* performing the 'self-check' to ensure the challenge record has propagated

* 'accepting' the authorization once the self check is passing.

* keeping the `status` field up to date with details of the challenge so that
the Order controller can make decisions based on the state of challenges.

One area to highlight, is the behaviour of the Challenge controller wrt. challenges
vs authorizations.

Whilst this controller works with a single ACME *Challenge* only, in order to
avoid introducing a third resource type (i.e. `Authorization`), the Challenge
controller is responsible for accepting the **ACME authorization** associated
with the challenge.

After the authorization has been accepted, the `status.state` field of the
Challenge resource will be set to the state of the **authorization**. The state
of a Challenge resource will only be 'valid' when its corresponding ACME
authorization is 'valid'.

Authorization & challenge status is closely related, so this should not bring any
unexpected surprises (i.e. if a challenge is 'invalid', the authorization will also
be 'invalid' and vice-versa).

### Refactoring

There will be some significant refactoring work required to accommodate this change.
Notably, the ACME specific client handling in the `pkg/issuer/acme` directory
will need breaking out into a shared package so that the new Order and Challenge
controllers can re-use this code.

The majority of this refactoring can be done in separate PRs to make it easier
to review.

## Risks & mitigations

#### Introducing new resource types creates more cognitive overhead for users, and a steeper 'on-boarding' curve wrt debugging issues.

This is mitigated by:

* Users will never need to create these resources themselves.
* The user-facing API (i.e. the current Certificate and (Cluster)Issuer resources)
will stay the same.
* The 'certificates' controller can aggregate failure reasons from the 'order'
resource it is managing, to save users having to dig into the specifics of the
Order & Challenge.
* The 'order' controller can aggregate failure reasons from the 'challenge'
resources it is managing in a similar way.
* We can also include debugging information on the Certificate resource itself,
e.g. storing messages such as `You can get more information about why this order
failed by running 'kubectl describe order -n <namespace> <order-name>'

## Alternatives considered

#### Expanding the `certificate.status.acme` stanza to include more fields tracking the state of the current order

This **would** help efforts to reduce the number of calls to the ACME server that
are required.

However, because Certificate resources are mutable, we would also need to build
in fairly complex 'change detection' logic, and subsequently handle cleaning up
in-progress orders that have been cancelled properly.

This becomes difficult to manage effectively, and especially test.

It is also very difficult to handle effective rate limiting when using this
strategy, as it will mean even more code going into the `Prepare` function of
the ACME issuer.
