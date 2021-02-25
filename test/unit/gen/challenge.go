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

package gen

import (
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type ChallengeModifier func(*cmacme.Challenge)

func Challenge(name string, mods ...ChallengeModifier) *cmacme.Challenge {
	c := &cmacme.Challenge{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func ChallengeFrom(ch *cmacme.Challenge, mods ...ChallengeModifier) *cmacme.Challenge {
	ch = ch.DeepCopy()
	for _, mod := range mods {
		mod(ch)
	}
	return ch
}

func SetChallengeNamespace(ns string) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Namespace = ns
	}
}

func SetChallengeType(t cmacme.ACMEChallengeType) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Spec.Type = t
	}
}

func SetChallengeToken(t string) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Spec.Token = t
	}
}

// SetIssuer sets the challenge.spec.issuerRef field
func SetChallengeIssuer(o cmmeta.ObjectReference) ChallengeModifier {
	return func(c *cmacme.Challenge) {
		c.Spec.IssuerRef = o
	}
}

func SetChallengeDNSName(dnsName string) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Spec.DNSName = dnsName
	}
}

func SetChallengePresented(p bool) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Status.Presented = p
	}
}

func SetChallengeWildcard(p bool) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Spec.Wildcard = p
	}
}

func SetChallengeState(s cmacme.State) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Status.State = s
	}
}

func SetChallengeReason(s string) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Status.Reason = s
	}
}

func SetChallengeURL(s string) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Spec.URL = s
	}
}

func SetChallengeProcessing(b bool) ChallengeModifier {
	return func(ch *cmacme.Challenge) {
		ch.Status.Processing = b
	}
}
