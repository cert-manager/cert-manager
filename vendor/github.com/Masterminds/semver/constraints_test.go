package semver

import "testing"

func TestParseConstraint(t *testing.T) {
	tests := []struct {
		in  string
		c   Constraint
		err bool
	}{
		{"*", Any(), false},
		{">= 1.2", rangeConstraint{
			min:        newV(1, 2, 0),
			max:        Version{special: infiniteVersion},
			includeMin: true,
		}, false},
		{"1.0", newV(1, 0, 0), false},
		{"foo", nil, true},
		{"<= 1.2", rangeConstraint{
			min:        Version{special: zeroVersion},
			max:        newV(1, 2, 0),
			includeMax: true,
		}, false},
		{"=< 1.2", rangeConstraint{
			min:        Version{special: zeroVersion},
			max:        newV(1, 2, 0),
			includeMax: true,
		}, false},
		{"=> 1.2", rangeConstraint{
			min:        newV(1, 2, 0),
			max:        Version{special: infiniteVersion},
			includeMin: true,
		}, false},
		{"v1.2", newV(1, 2, 0), false},
		{"=1.5", newV(1, 5, 0), false},
		{"> 1.3", rangeConstraint{
			min: newV(1, 3, 0),
			max: Version{special: infiniteVersion},
		}, false},
		{"< 1.4.1", rangeConstraint{
			min: Version{special: zeroVersion},
			max: newV(1, 4, 1),
		}, false},
		{"~1.1.0", rangeConstraint{
			min:        newV(1, 1, 0),
			max:        newV(1, 2, 0),
			includeMin: true,
			includeMax: false,
		}, false},
		{"^1.1.0", rangeConstraint{
			min:        newV(1, 1, 0),
			max:        newV(2, 0, 0),
			includeMin: true,
			includeMax: false,
		}, false},
	}

	for _, tc := range tests {
		c, err := parseConstraint(tc.in, false)
		if tc.err && err == nil {
			t.Errorf("Expected error for %s didn't occur", tc.in)
		} else if !tc.err && err != nil {
			t.Errorf("Unexpected error %q for %s", err, tc.in)
		}

		// If an error was expected continue the loop and don't try the other
		// tests as they will cause errors.
		if tc.err {
			continue
		}

		if !constraintEq(tc.c, c) {
			t.Errorf("%q produced constraint %q, but expected %q", tc.in, c, tc.c)
		}
	}
}

func constraintEq(c1, c2 Constraint) bool {
	switch tc1 := c1.(type) {
	case any:
		if _, ok := c2.(any); !ok {
			return false
		}
		return true
	case none:
		if _, ok := c2.(none); !ok {
			return false
		}
		return true
	case Version:
		if tc2, ok := c2.(Version); ok {
			return tc1.Equal(tc2)
		}
		return false
	case rangeConstraint:
		if tc2, ok := c2.(rangeConstraint); ok {
			if len(tc1.excl) != len(tc2.excl) {
				return false
			}

			if !tc1.minIsZero() {
				if !(tc1.includeMin == tc2.includeMin && tc1.min.Equal(tc2.min)) {
					return false
				}
			} else if !tc2.minIsZero() {
				return false
			}

			if !tc1.maxIsInf() {
				if !(tc1.includeMax == tc2.includeMax && tc1.max.Equal(tc2.max)) {
					return false
				}
			} else if !tc2.maxIsInf() {
				return false
			}

			for k, e := range tc1.excl {
				if !e.Equal(tc2.excl[k]) {
					return false
				}
			}
			return true
		}
		return false
	case unionConstraint:
		if tc2, ok := c2.(unionConstraint); ok {
			if len(tc1) != len(tc2) {
				return false
			}

			for k, c := range tc1 {
				if !constraintEq(c, tc2[k]) {
					return false
				}
			}
			return true
		}
		return false
	}

	panic("unknown type")
}

// newV is a helper to create a new Version object.
func newV(major, minor, patch uint64) Version {
	return Version{
		major: major,
		minor: minor,
		patch: patch,
	}
}

func TestConstraintCheck(t *testing.T) {
	tests := []struct {
		constraint string
		version    string
		check      bool
	}{
		{"= 2.0", "1.2.3", false},
		{"= 2.0", "2.0.0", true},
		{"4.1", "4.1.0", true},
		{"!=4.1", "4.1.0", false},
		{"!=4.1", "5.1.0", true},
		{">1.1", "4.1.0", true},
		{">1.1", "1.1.0", false},
		{"<1.1", "0.1.0", true},
		{"<1.1", "1.1.0", false},
		{"<1.1", "1.1.1", false},
		{">=1.1", "4.1.0", true},
		{">=1.1", "1.1.0", true},
		{">=1.1", "0.0.9", false},
		{"<=1.1", "0.1.0", true},
		{"<=1.1", "1.1.0", true},
		{"<=1.1", "1.1.1", false},
		{"<=1.1-alpha1", "1.1", false},
		{"<=2.x", "3.0.0", false},
		{"<=2.x", "2.9.9", true},
		{"<2.x", "2.0.0", false},
		{"<2.x", "1.9.9", true},
		{">=2.x", "3.0.0", true},
		{">=2.x", "2.9.9", true},
		{">=2.x", "1.9.9", false},
		{">2.x", "3.0.0", true},
		{">2.x", "2.9.9", false},
		{">2.x", "1.9.9", false},
		{"<=2.x-alpha2", "3.0.0-alpha3", false},
		{"<=2.0.0", "2.0.0-alpha1", false},
		{">2.x-beta1", "3.0.0-alpha2", false},
		{"^2.0.0", "3.0.0-alpha2", false},
		{"^2.0.0", "2.0.0-alpha1", false},
		{"^2.1.0-alpha1", "2.1.0-alpha2", true},  // allow prerelease match within same major/minor/patch
		{"^2.1.0-alpha1", "2.1.1-alpha2", false}, // but ONLY within same major/minor/patch
		{"^2.1.0-alpha3", "2.1.0-alpha2", false}, // still respect prerelease ordering
		{"^2.0.0", "2.0.0-alpha2", false},        // and only if the min has a prerelease
	}

	for _, tc := range tests {
		if testing.Verbose() {
			t.Logf("Testing if %q allows %q", tc.constraint, tc.version)
		}
		c, err := parseConstraint(tc.constraint, false)
		if err != nil {
			t.Errorf("err: %s", err)
			continue
		}

		v, err := NewVersion(tc.version)
		if err != nil {
			t.Errorf("err: %s", err)
			continue
		}

		a := c.Matches(v) == nil
		if a != tc.check {
			if tc.check {
				t.Errorf("%q should have matched %q", tc.constraint, tc.version)
			} else {
				t.Errorf("%q should not have matched %q", tc.constraint, tc.version)
			}
		}
	}
}

func TestNewConstraint(t *testing.T) {
	tests := []struct {
		input string
		c     Constraint
		err   bool
	}{
		{">= 1.1", rangeConstraint{
			min:        newV(1, 1, 0),
			max:        Version{special: infiniteVersion},
			includeMin: true,
		}, false},
		{"2.0", newV(2, 0, 0), false},
		{">= bar", nil, true},
		{"^1.1.0", rangeConstraint{
			min:        newV(1, 1, 0),
			max:        newV(2, 0, 0),
			includeMin: true,
		}, false},
		{">= 1.2.3, < 2.0 || => 3.0, < 4", unionConstraint{
			rangeConstraint{
				min:        newV(1, 2, 3),
				max:        newV(2, 0, 0),
				includeMin: true,
			},
			rangeConstraint{
				min:        newV(3, 0, 0),
				max:        newV(4, 0, 0),
				includeMin: true,
			},
		}, false},
		{"3 - 4 || => 1.0, < 2", Union(
			rangeConstraint{
				min:        newV(3, 0, 0),
				max:        newV(4, 0, 0),
				includeMin: true,
				includeMax: true,
			},
			rangeConstraint{
				min:        newV(1, 0, 0),
				max:        newV(2, 0, 0),
				includeMin: true,
			},
		), false},
		// demonstrates union compression
		{"3 - 4 || => 3.0, < 4", rangeConstraint{
			min:        newV(3, 0, 0),
			max:        newV(4, 0, 0),
			includeMin: true,
			includeMax: true,
		}, false},
		{">=1.1.0, <2.0.0", rangeConstraint{
			min:        newV(1, 1, 0),
			max:        newV(2, 0, 0),
			includeMin: true,
			includeMax: false,
		}, false},
		{"!=1.4.0", rangeConstraint{
			min: Version{special: zeroVersion},
			max: Version{special: infiniteVersion},
			excl: []Version{
				newV(1, 4, 0),
			},
		}, false},
		{">=1.1.0, !=1.4.0", rangeConstraint{
			min:        newV(1, 1, 0),
			max:        Version{special: infiniteVersion},
			includeMin: true,
			excl: []Version{
				newV(1, 4, 0),
			},
		}, false},
		{"1.1.0 - 12-abc123", rangeConstraint{
			min:        newV(1,1,0),
			max:        Version{major: 12, minor: 0, patch: 0, pre: "abc123"},
			includeMin: true,
			includeMax: true,
		}, false},
		{"1.1.0-12-abc123", Version{
			major: 1,
			minor: 1,
			patch: 0,
			pre: "12-abc123"}, false},
	}

	for _, tc := range tests {
		c, err := NewConstraint(tc.input)
		if tc.err && err == nil {
			t.Errorf("expected but did not get error for: %s", tc.input)
			continue
		} else if !tc.err && err != nil {
			t.Errorf("unexpectederror for input %s: %s", tc.input, err)
			continue
		}
		if tc.err {
			continue
		}

		if !constraintEq(tc.c, c) {
			t.Errorf("%q produced constraint %q, but expected %q", tc.input, c, tc.c)
		}
	}
}

func TestNewConstraintIC(t *testing.T) {
	tests := []struct {
		input string
		c     Constraint
		err   bool
	}{
		{"=2.0", newV(2, 0, 0), false},
		{"= 2.0", newV(2, 0, 0), false},
		{"1.1.0", rangeConstraint{
			min:        newV(1, 1, 0),
			max:        newV(2, 0, 0),
			includeMin: true,
		}, false},
		{"1.1", rangeConstraint{
			min:        newV(1, 1, 0),
			max:        newV(2, 0, 0),
			includeMin: true,
		}, false},
	}

	for _, tc := range tests {
		c, err := NewConstraintIC(tc.input)
		if tc.err && err == nil {
			t.Errorf("expected but did not get error for: %s", tc.input)
			continue
		} else if !tc.err && err != nil {
			t.Errorf("unexpectederror for input %s: %s", tc.input, err)
			continue
		}
		if tc.err {
			continue
		}

		if !constraintEq(tc.c, c) {
			t.Errorf("%q produced constraint %q, but expected %q", tc.input, c, tc.c)
		}
	}
}

func TestConstraintsCheck(t *testing.T) {
	tests := []struct {
		constraint string
		version    string
		check      bool
	}{
		{"*", "1.2.3", true},
		{"~0.0.0", "1.2.3", false},
		{"0.x.x", "1.2.3", false},
		{"0.0.x", "1.2.3", false},
		{"~0.0.0", "0.1.9", false},
		{"~0.0.0", "0.0.9", true},
		{"^0.0.0", "0.0.9", true},
		{"^0.0.0", "0.1.9", false}, // caret behaves like tilde below 1.0.0
		{"= 2.0", "1.2.3", false},
		{"= 2.0", "2.0.0", true},
		{"4.1", "4.1.0", true},
		{"4.1.x", "4.1.3", true},
		{"1.x", "1.4", true},
		{"!=4.1", "4.1.0", false},
		{"!=4.1", "5.1.0", true},
		{"!=4.x", "5.1.0", true},
		{"!=4.x", "4.1.0", false},
		{"!=4.1.x", "4.2.0", true},
		{"!=4.2.x", "4.2.3", false},
		{">1.1", "4.1.0", true},
		{">1.1", "1.1.0", false},
		{"<1.1", "0.1.0", true},
		{"<1.1", "1.1.0", false},
		{"<1.1", "1.1.1", false},
		{"<1.x", "1.1.1", false},
		{"<1.x", "0.9.1", true},
		{"<1.x", "2.1.1", false},
		{"<1.1.x", "1.2.1", false},
		{"<1.1.x", "1.1.500", false},
		{"<1.1.x", "1.0.500", true},
		{"<1.2.x", "1.1.1", true},
		{">=1.1", "4.1.0", true},
		{">=1.1", "1.1.0", true},
		{">=1.1", "0.0.9", false},
		{"<=1.1", "0.1.0", true},
		{"<=1.1", "1.1.0", true},
		{"<=1.x", "1.1.0", true},
		{"<=2.x", "3.1.0", false},
		{"<=1.1", "1.1.1", false},
		{"<=1.1.x", "1.2.500", false},
		{">1.1, <2", "1.1.1", true},
		{">1.1, <3", "4.3.2", false},
		{">=1.1, <2, !=1.2.3", "1.2.3", false},
		{">=1.1, <2, !=1.2.3 || > 3", "3.1.2", true},
		{">=1.1, <2, !=1.2.3 || >= 3", "3.0.0", true},
		{">=1.1, <2, !=1.2.3 || > 3", "3.0.0", false},
		{">=1.1, <2, !=1.2.3 || > 3", "1.2.3", false},
		{"1.1 - 2", "1.1.1", true},
		{"1.1-3", "4.3.2", false},
		{"^1.1", "1.1.1", true},
		{"^1.1", "4.3.2", false},
		{"^1.x", "1.1.1", true},
		{"^2.x", "1.1.1", false},
		{"^1.x", "2.1.1", false},
		{"~*", "2.1.1", true},
		{"~1.x", "2.1.1", false},
		{"~1.x", "1.3.5", true},
		{"~1.x", "1.4", true},
		{"~1.1", "1.1.1", true},
		{"~1.2.3", "1.2.5", true},
		{"~1.2.3", "1.2.2", false},
		{"~1.2.3", "1.3.2", false},
		{"~1.1", "1.2.3", false},
		{"~1.3", "2.4.5", false},
	}

	for _, tc := range tests {
		c, err := NewConstraint(tc.constraint)
		if err != nil {
			t.Errorf("err: %s", err)
			continue
		}

		v, err := NewVersion(tc.version)
		if err != nil {
			t.Errorf("err: %s", err)
			continue
		}

		a := c.Matches(v) == nil
		if a != tc.check {
			if a {
				t.Errorf("Input %q produced constraint %q; should not have admitted %q, but did", tc.constraint, c, tc.version)
			} else {
				t.Errorf("Input %q produced constraint %q; should have admitted %q, but did not", tc.constraint, c, tc.version)
			}
		}
	}
}

func TestBidirectionalSerialization(t *testing.T) {
	tests := []struct {
		io string
		eq bool
	}{
		{"*", true},         // any
		{"~0.0.0", false},   // tildes expand into ranges
		{"=2.0", false},     // abbreviated versions print as full
		{"4.1.x", false},    // wildcards expand into ranges
		{">= 1.1.0", false}, // does not produce spaces on ranges
		{"4.1.0", true},
		{"!=4.1.0", true},
		{">=1.1.0", true},
		{">1.0.0, <=1.1.0", true},
		{"<=1.1.0", true},
		{">=1.1.7, <1.3.0", true},  // tilde width
		{">=1.1.0, <=2.0.0", true}, // no unary op on lte max
		{">1.1.3, <2.0.0", true},   // no unary op on gt min
		{">1.1.0, <=2.0.0", true},  // no unary op on gt min and lte max
		{">=1.1.0, <=1.2.0", true}, // no unary op on lte max
		{">1.1.1, <1.2.0", true},   // no unary op on gt min
		{">1.1.7, <=2.0.0", true},  // no unary op on gt min and lte max
		{">1.1.7, <=2.0.0", true},  // no unary op on gt min and lte max
		{">=0.1.7, <1.0.0", true},  // caret shifting below 1.0.0
		{">=0.1.7, <0.3.0", true},  // caret shifting width below 1.0.0
	}

	for _, fix := range tests {
		c, err := NewConstraint(fix.io)
		if err != nil {
			t.Errorf("Valid constraint string produced unexpected error: %s", err)
		}

		eq := fix.io == c.String()
		if eq != fix.eq {
			if eq {
				t.Errorf("Constraint %q should not have reproduced input string %q, but did", c, fix.io)
			} else {
				t.Errorf("Constraint should have reproduced input string %q, but instead produced %q", fix.io, c)
			}
		}
	}
}

func TestBidirectionalSerializationIC(t *testing.T) {
	tests := []struct {
		io string
		eq bool
	}{
		{"*", true},      // any
		{"=2.0.0", true}, // versions retain leading =
		{"2.0.0", true},  // (no) caret in, (no) caret out
	}

	for _, fix := range tests {
		c, err := NewConstraintIC(fix.io)
		if err != nil {
			t.Errorf("Valid constraint string produced unexpected error: %s", err)
		}

		eq := fix.io == c.ImpliedCaretString()
		if eq != fix.eq {
			if eq {
				t.Errorf("Constraint %q should not have reproduced input string %q, but did", c, fix.io)
			} else {
				t.Errorf("Constraint should have reproduced input string %q, but instead produced %q", fix.io, c)
			}
		}
	}
}

func TestPreferUnaryOpForm(t *testing.T) {
	tests := []struct {
		in, out string
	}{
		{">=0.1.7, <0.2.0", "^0.1.7"}, // caret shifting below 1.0.0
		{">=1.1.0, <2.0.0", "^1.1.0"},
		{">=1.1.0, <2.0.0, !=1.2.3", "^1.1.0, !=1.2.3"},
	}

	for _, fix := range tests {
		c, err := NewConstraint(fix.in)
		if err != nil {
			t.Errorf("Valid constraint string produced unexpected error: %s", err)
		}

		if fix.out != c.String() {
			t.Errorf("Constraint %q was not transformed into expected output string %q", fix.in, fix.out)
		}
	}
}

func TestRewriteRange(t *testing.T) {
	tests := []struct {
		c  string
		nc string
	}{
		{"2 - 3", ">= 2, <= 3"},
		{"2 - 3, 2 - 3", ">= 2, <= 3,>= 2, <= 3"},
		{"2 - 3, 4.0.0 - 5.1", ">= 2, <= 3,>= 4.0.0, <= 5.1"},
	}

	for _, tc := range tests {
		o := rewriteRange(tc.c)

		if o != tc.nc {
			t.Errorf("Range %s rewritten incorrectly as '%s'", tc.c, o)
		}
	}
}

func TestRewriteRange_InvalidRange(t *testing.T) {
	// Ranges require a space to be recognized

	tests := []struct {
		c  string
		nc string
	}{
		{"2-3", "2-3"},
		{"2-3, 2 - 3","2-3,>= 2, <= 3"},
		{"2-3, 4.0.0 - 5.1", "2-3,>= 4.0.0, <= 5.1"},
	}

	for _, tc := range tests {
		o := rewriteRange(tc.c)

		if o != tc.nc {
			t.Errorf("Range %s rewritten incorrectly as '%s'", tc.c, o)
		}
	}
}

func TestIsX(t *testing.T) {
	tests := []struct {
		t string
		c bool
	}{
		{"A", false},
		{"%", false},
		{"X", true},
		{"x", true},
		{"*", true},
	}

	for _, tc := range tests {
		a := isX(tc.t)
		if a != tc.c {
			t.Errorf("Function isX error on %s", tc.t)
		}
	}
}

func TestUnionErr(t *testing.T) {
	u1 := Union(
		rangeConstraint{
			min:        newV(3, 0, 0),
			max:        newV(4, 0, 0),
			includeMin: true,
			includeMax: true,
		},
		rangeConstraint{
			min:        newV(1, 0, 0),
			max:        newV(2, 0, 0),
			includeMin: true,
		},
	)
	fail := u1.Matches(newV(2, 5, 0))
	failstr := `2.5.0 is greater than or equal to the maximum of ^1.0.0
2.5.0 is less than the minimum of >=3.0.0, <=4.0.0`
	if fail.Error() != failstr {
		t.Errorf("Did not get expected failure message from union, got %q", fail)
	}
}

func TestIsSuperset(t *testing.T) {
	rc := []rangeConstraint{
		{
			min:        newV(1, 2, 0),
			max:        newV(2, 0, 0),
			includeMin: true,
		},
		{
			min: newV(1, 2, 0),
			max: newV(2, 1, 0),
		},
		{
			min: Version{special: zeroVersion},
			max: newV(1, 10, 0),
		},
		{
			min: newV(2, 0, 0),
			max: Version{special: infiniteVersion},
		},
		{
			min:        newV(1, 2, 0),
			max:        newV(2, 0, 0),
			includeMax: true,
		},
	}

	for _, c := range rc {

		// Superset comparison is not strict, so a range should always be a superset
		// of itself.
		if !c.isSupersetOf(c) {
			t.Errorf("Ranges should be supersets of themselves; %s indicated it was not", c)
		}
	}

	pairs := []struct{ l, r rangeConstraint }{
		{
			// ensures lte is handled correctly (min side)
			l: rc[0],
			r: rc[1],
		},
		{
			// ensures nil on min side works well
			l: rc[0],
			r: rc[2],
		},
		{
			// ensures nil on max side works well
			l: rc[0],
			r: rc[3],
		},
		{
			// ensures nils on both sides work well
			l: rc[2],
			r: rc[3],
		},
		{
			// ensures gte is handled correctly (max side)
			l: rc[2],
			r: rc[4],
		},
	}

	for _, p := range pairs {
		if p.l.isSupersetOf(p.r) {
			t.Errorf("%s is not a superset of %s", p.l, p.r)
		}
		if p.r.isSupersetOf(p.l) {
			t.Errorf("%s is not a superset of %s", p.r, p.l)
		}
	}

	rc[1].max.minor = 0

	if !rc[0].isSupersetOf(rc[1]) {
		t.Errorf("%s is a superset of %s", rc[0], rc[1])
	}
	rc[1].includeMax = true
	if rc[1].isSupersetOf(rc[0]) {
		t.Errorf("%s is not a superset of %s", rc[1], rc[0])
	}
	rc[0].includeMin = false
	if !rc[1].isSupersetOf(rc[0]) {
		t.Errorf("%s is a superset of %s", rc[1], rc[0])
	}

	// isSupersetOf ignores excludes, so even though this would make rc[1] not a
	// superset of rc[0] anymore, it should still say it is.
	rc[1].excl = []Version{
		newV(1, 5, 0),
	}

	if !rc[1].isSupersetOf(rc[0]) {
		t.Errorf("%s is still a superset of %s, because isSupersetOf is supposed to ignore excluded versions", rc[1], rc[0])
	}
}
