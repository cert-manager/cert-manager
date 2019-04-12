package dns

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/wait"
)

// TestBasicPresentRecord will perform a basic validation that the Present
// method works as expected.
// It will call Present and then poll the configured DNS server until the
// record has propagated.
// Afterwards, it will call CleanUp to clean up the changes it has made.
// If either Present or CleanUp fail to properly present and clean up the
// challenge record, this test case will fail.
func (f *fixture) TestBasicPresentRecord(t *testing.T) {
	ns, cleanup := f.setupNamespace(t, "basic-present-record")
	defer cleanup()
	ch := f.buildChallengeRequest(t, ns)

	// present the record
	if err := f.testSolver.Present(ch); err != nil {
		t.Errorf("expected Present to not error, but got: %v", err)
		return
	}
	defer f.testSolver.CleanUp(ch)

	// wait until the record has propagated
	if err := wait.PollUntil(defaultPollInterval,
		f.recordHasPropagatedCheck(ch.ResolvedFQDN, ch.Challenge.Spec.Key),
		closingStopCh(defaultPropagationLimit)); err != nil {
			t.Errorf("error waiting for DNS record propagation: %v", err)
			return
	}

	// clean up the presented record
	if err := f.testSolver.CleanUp(ch); err != nil {
		t.Errorf("expected CleanUp to not error, but got: %v", err)
	}

	// wait until the record has been deleted
	if err := wait.PollUntil(defaultPollInterval,
		f.recordHasBeenDeletedCheck(ch.ResolvedFQDN, ch.Challenge.Spec.Key),
		closingStopCh(defaultPropagationLimit)); err != nil {
			t.Errorf("error waiting for record to be deleted: %v", err)
			return
	}
}

// TestExtendedSupportsMultipleSameDomain validates that a DNS01 provider
// supports setting multiple TXT records for the same DNS record name.
// Adding a new record **must not** delete existing records with the same
// record name from the DNS zone.
func (f *fixture) TestExtendedDeletingOneRecordRetainsOthers(t *testing.T) {
	if !f.strictMode {
		t.Skip("skipping test as strict mode is disabled, see: https://github.com/jetstack/cert-manager/pull/1354")
	}

	ns, cleanup := f.setupNamespace(t, "extended-supports-multiple-same-domain")
	defer cleanup()
	ch := f.buildChallengeRequest(t, ns)
	ch2 := f.buildChallengeRequest(t, ns)
	ch2.Challenge.Spec.Key = "anothertestingkey"

	// present the first record
	if err := f.testSolver.Present(ch); err != nil {
		t.Errorf("expected Present to not error, but got: %v", err)
		return
	}
	defer f.testSolver.CleanUp(ch)

	// present the second record
	if err := f.testSolver.Present(ch2); err != nil {
		t.Errorf("expected Present to not error, but got: %v", err)
		return
	}
	defer f.testSolver.CleanUp(ch2)

	// wait until all records have propagated
	if err := wait.PollUntil(defaultPollInterval,
		allConditions(
			f.recordHasPropagatedCheck(ch.ResolvedFQDN, ch.Challenge.Spec.Key),
			f.recordHasPropagatedCheck(ch2.ResolvedFQDN, ch2.Challenge.Spec.Key),
		),
		closingStopCh(defaultPropagationLimit)); err != nil {
		t.Errorf("error waiting for DNS record propagation: %v", err)
		return
	}

	// clean up the second record
	if err := f.testSolver.CleanUp(ch2); err != nil {
		t.Errorf("expected CleanUp to not error, but got: %v", err)
	}

	// wait until the second record has been deleted and the first one remains
	if err := wait.PollUntil(defaultPollInterval,
		allConditions(
			f.recordHasBeenDeletedCheck(ch2.ResolvedFQDN, ch2.Challenge.Spec.Key),
			f.recordHasPropagatedCheck(ch.ResolvedFQDN, ch.Challenge.Spec.Key),
		),
		closingStopCh(defaultPropagationLimit)); err != nil {
		t.Errorf("error waiting for DNS record propagation: %v", err)
		return
	}
}
