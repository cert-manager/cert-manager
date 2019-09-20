/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package gen

import (
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

type ChallengeModifier func(*v1alpha2.Challenge)

func Challenge(name string, mods ...ChallengeModifier) *v1alpha2.Challenge {
	c := &v1alpha2.Challenge{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func ChallengeFrom(ch *v1alpha2.Challenge, mods ...ChallengeModifier) *v1alpha2.Challenge {
	ch = ch.DeepCopy()
	for _, mod := range mods {
		mod(ch)
	}
	return ch
}

func SetChallengeType(t string) ChallengeModifier {
	return func(ch *v1alpha2.Challenge) {
		ch.Spec.Type = v1alpha2.ACMEChallengeType(t)
	}
}

// SetIssuer sets the challenge.spec.issuerRef field
func SetChallengeIssuer(o cmmeta.ObjectReference) ChallengeModifier {
	return func(c *v1alpha2.Challenge) {
		c.Spec.IssuerRef = o
	}
}

func SetChallengeDNSName(dnsName string) ChallengeModifier {
	return func(ch *v1alpha2.Challenge) {
		ch.Spec.DNSName = dnsName
	}
}

func SetChallengePresented(p bool) ChallengeModifier {
	return func(ch *v1alpha2.Challenge) {
		ch.Status.Presented = p
	}
}

func SetChallengeWildcard(p bool) ChallengeModifier {
	return func(ch *v1alpha2.Challenge) {
		ch.Spec.Wildcard = p
	}
}

func SetChallengeState(s v1alpha2.State) ChallengeModifier {
	return func(ch *v1alpha2.Challenge) {
		ch.Status.State = s
	}
}

func SetChallengeReason(s string) ChallengeModifier {
	return func(ch *v1alpha2.Challenge) {
		ch.Status.Reason = s
	}
}

func SetChallengeURL(s string) ChallengeModifier {
	return func(ch *v1alpha2.Challenge) {
		ch.Spec.URL = s
	}
}

func SetChallengeProcessing(b bool) ChallengeModifier {
	return func(ch *v1alpha2.Challenge) {
		ch.Status.Processing = b
	}
}
