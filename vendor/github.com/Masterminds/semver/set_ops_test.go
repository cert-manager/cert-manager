package semver

import "testing"

func TestIntersection(t *testing.T) {
	var actual Constraint
	rc1 := rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 0, 0),
	}

	if actual = Intersection(); !IsNone(actual) {
		t.Errorf("Intersection of nothing should always produce None; got %q", actual)
	}

	if actual = Intersection(rc1); !constraintEq(actual, rc1) {
		t.Errorf("Intersection of one item should always return that item; got %q", actual)
	}

	if actual = Intersection(rc1, None()); !IsNone(actual) {
		t.Errorf("Intersection of anything with None should always produce None; got %q", actual)
	}

	if actual = Intersection(rc1, Any()); !constraintEq(actual, rc1) {
		t.Errorf("Intersection of anything with Any should return self; got %q", actual)
	}

	v1 := newV(1, 5, 0)
	if actual = Intersection(rc1, v1); !constraintEq(actual, v1) {
		t.Errorf("Got constraint %q, but expected %q", actual, v1)
	}

	rc2 := rangeConstraint{
		min: newV(1, 2, 0),
		max: newV(2, 2, 0),
	}
	result := rangeConstraint{
		min: newV(1, 2, 0),
		max: newV(2, 0, 0),
	}

	if actual = Intersection(rc1, rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	u1 := unionConstraint{
		rangeConstraint{
			min: newV(1, 2, 0),
			max: newV(3, 0, 0),
		},
		newV(3, 1, 0),
	}

	if actual = Intersection(u1, rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = Intersection(rc1, newV(2, 0, 5), u1); !IsNone(actual) {
		t.Errorf("First two are disjoint, should have gotten None but got %q", actual)
	}
}

func TestRangeIntersection(t *testing.T) {
	var actual Constraint
	// Test magic cases
	rc1 := rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 0, 0),
	}
	if actual = rc1.Intersect(Any()); !constraintEq(actual, rc1) {
		t.Errorf("Intersection of anything with Any should return self; got %q", actual)
	}
	if actual = rc1.Intersect(None()); !IsNone(actual) {
		t.Errorf("Intersection of anything with None should always produce None; got %q", actual)
	}

	// Test single version cases

	// single v, in range
	v1 := newV(1, 5, 0)

	if actual = rc1.Intersect(v1); !constraintEq(actual, v1) {
		t.Errorf("Intersection of version with matching range should return the version; got %q", actual)
	}

	// now exclude just that version
	rc1.excl = []Version{v1}
	if actual = rc1.Intersect(v1); !IsNone(actual) {
		t.Errorf("Intersection of version with range having specific exclude for that version should produce None; got %q", actual)
	}

	// and, of course, none if the version is out of range
	v2 := newV(0, 5, 0)
	if actual = rc1.Intersect(v2); !IsNone(actual) {
		t.Errorf("Intersection of version with non-matching range should produce None; got %q", actual)
	}

	// Test basic overlap case
	rc1 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 0, 0),
	}
	rc2 := rangeConstraint{
		min: newV(1, 2, 0),
		max: newV(2, 2, 0),
	}
	result := rangeConstraint{
		min: newV(1, 2, 0),
		max: newV(2, 0, 0),
	}

	if actual = rc1.Intersect(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// And with includes
	rc1.includeMin = true
	rc1.includeMax = true
	rc2.includeMin = true
	rc2.includeMax = true
	result.includeMin = true
	result.includeMax = true

	if actual = rc1.Intersect(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// Overlaps with nils
	rc1 = rangeConstraint{
		min: newV(1, 0, 0),
		max: Version{special: infiniteVersion},
	}
	rc2 = rangeConstraint{
		min: Version{special: zeroVersion},
		max: newV(2, 2, 0),
	}
	result = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 2, 0),
	}

	if actual = rc1.Intersect(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// And with includes
	rc1.includeMin = true
	rc2.includeMax = true
	result.includeMin = true
	result.includeMax = true

	if actual = rc1.Intersect(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// Test superset overlap case
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
	}
	rc2 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(3, 0, 0),
	}
	result = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
	}

	if actual = rc1.Intersect(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// Make sure irrelevant includes don't leak in
	rc2.includeMin = true
	rc2.includeMax = true

	if actual = rc1.Intersect(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// But relevant includes get used
	rc1.includeMin = true
	rc1.includeMax = true
	result.includeMin = true
	result.includeMax = true

	if actual = rc1.Intersect(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// Test disjoint case
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(1, 6, 0),
	}
	rc2 = rangeConstraint{
		min: newV(2, 0, 0),
		max: newV(3, 0, 0),
	}

	if actual = rc1.Intersect(rc2); !constraintEq(actual, None()) {
		t.Errorf("Got constraint %q, but expected %q", actual, None())
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, None()) {
		t.Errorf("Got constraint %q, but expected %q", actual, None())
	}

	// Test disjoint at gt/lt boundary (non-adjacent)
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
	}
	rc2 = rangeConstraint{
		min: newV(2, 0, 0),
		max: newV(3, 0, 0),
	}

	if actual = rc1.Intersect(rc2); !constraintEq(actual, None()) {
		t.Errorf("Got constraint %q, but expected %q", actual, None())
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, None()) {
		t.Errorf("Got constraint %q, but expected %q", actual, None())
	}

	// Now, just have them touch at a single version
	rc1.includeMax = true
	rc2.includeMin = true

	vresult := newV(2, 0, 0)
	if actual = rc1.Intersect(rc2); !constraintEq(actual, vresult) {
		t.Errorf("Got constraint %q, but expected %q", actual, vresult)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, vresult) {
		t.Errorf("Got constraint %q, but expected %q", actual, vresult)
	}

	// Test excludes in intersection range
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
		excl: []Version{
			newV(1, 6, 0),
		},
	}
	rc2 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(3, 0, 0),
	}

	if actual = rc1.Intersect(rc2); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}

	// Test excludes not in intersection range
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
	}
	rc2 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(3, 0, 0),
		excl: []Version{
			newV(1, 1, 0),
		},
	}

	if actual = rc1.Intersect(rc2); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}

	// Test min, and greater min
	rc1 = rangeConstraint{
		min: newV(1, 0, 0),
		max: Version{special: infiniteVersion},
	}
	rc2 = rangeConstraint{
		min:        newV(1, 5, 0),
		max:        Version{special: infiniteVersion},
		includeMin: true,
	}

	if actual = rc1.Intersect(rc2); !constraintEq(actual, rc2) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, rc2) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// Test max, and lesser max
	rc1 = rangeConstraint{
		max: newV(1, 0, 0),
	}
	rc2 = rangeConstraint{
		max: newV(1, 5, 0),
	}
	result = rangeConstraint{
		max: newV(1, 0, 0),
	}

	if actual = rc1.Intersect(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Intersect(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// Ensure pure excludes come through as they should
	rc1 = rangeConstraint{
		min: Version{special: zeroVersion},
		max: Version{special: infiniteVersion},
		excl: []Version{
			newV(1, 6, 0),
		},
	}

	rc2 = rangeConstraint{
		min: Version{special: zeroVersion},
		max: Version{special: infiniteVersion},
		excl: []Version{
			newV(1, 6, 0),
			newV(1, 7, 0),
		},
	}

	if actual = Any().Intersect(rc1); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}
	if actual = rc1.Intersect(Any()); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}
	if actual = rc1.Intersect(rc2); !constraintEq(actual, rc2) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc2)
	}

	// TODO test the pre-release special range stuff
}

func TestRangeUnion(t *testing.T) {
	var actual Constraint
	// Test magic cases
	rc1 := rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 0, 0),
	}
	if actual = rc1.Union(Any()); !IsAny(actual) {
		t.Errorf("Union of anything with Any should always produce Any; got %q", actual)
	}
	if actual = rc1.Union(None()); !constraintEq(actual, rc1) {
		t.Errorf("Union of anything with None should return self; got %q", actual)
	}

	// Test single version cases

	// single v, in range
	v1 := newV(1, 5, 0)

	if actual = rc1.Union(v1); !constraintEq(actual, rc1) {
		t.Errorf("Union of version with matching range should return the range; got %q", actual)
	}

	// now exclude just that version
	rc2 := rc1.dup()
	rc2.excl = []Version{v1}
	if actual = rc2.Union(v1); !constraintEq(actual, rc1) {
		t.Errorf("Union of version with range having specific exclude for that version should produce the range without that exclude; got %q", actual)
	}

	// and a union if the version is not within the range
	v2 := newV(0, 5, 0)
	uresult := unionConstraint{v2, rc1}
	if actual = rc1.Union(v2); !constraintEq(actual, uresult) {
		t.Errorf("Union of version with non-matching range should produce a unionConstraint with those two; got %q", actual)
	}

	// union with version at the min should ensure "oreq"
	v2 = newV(1, 0, 0)
	rc3 := rc1
	rc3.includeMin = true

	if actual = rc1.Union(v2); !constraintEq(actual, rc3) {
		t.Errorf("Union of range with version at min end should add includeMin (%q), but got %q", rc3, actual)
	}
	if actual = v2.Union(rc1); !constraintEq(actual, rc3) {
		t.Errorf("Union of range with version at min end should add includeMin (%q), but got %q", rc3, actual)
	}

	// same at max end
	v2 = newV(2, 0, 0)
	rc3.includeMin = false
	rc3.includeMax = true

	if actual = rc1.Union(v2); !constraintEq(actual, rc3) {
		t.Errorf("Union of range with version at max end should add includeMax (%q), but got %q", rc3, actual)
	}
	if actual = v2.Union(rc1); !constraintEq(actual, rc3) {
		t.Errorf("Union of range with version at max end should add includeMax (%q), but got %q", rc3, actual)
	}

	// Test basic overlap case
	rc1 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 0, 0),
	}
	rc2 = rangeConstraint{
		min: newV(1, 2, 0),
		max: newV(2, 2, 0),
	}
	result := rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 2, 0),
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// And with includes
	rc1.includeMin = true
	rc1.includeMax = true
	rc2.includeMin = true
	rc2.includeMax = true
	result.includeMin = true
	result.includeMax = true

	if actual = rc1.Union(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// Overlaps with nils
	rc1 = rangeConstraint{
		min: newV(1, 0, 0),
		max: Version{special: infiniteVersion},
	}
	rc2 = rangeConstraint{
		min: Version{special: zeroVersion},
		max: newV(2, 2, 0),
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, Any()) {
		t.Errorf("Got constraint %q, but expected %q", actual, Any())
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, Any()) {
		t.Errorf("Got constraint %q, but expected %q", actual, Any())
	}

	// Just one nil in overlap
	rc1.max = newV(2, 0, 0)
	result = rangeConstraint{
		min: Version{special: zeroVersion},
		max: newV(2, 2, 0),
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	rc1.max = Version{special: infiniteVersion}
	rc2.min = newV(1, 5, 0)
	result = rangeConstraint{
		min: newV(1, 0, 0),
		max: Version{special: infiniteVersion},
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// Test superset overlap case
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
	}
	rc2 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(3, 0, 0),
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, rc2) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc2)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, rc2) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc2)
	}

	// Test disjoint case
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(1, 6, 0),
	}
	rc2 = rangeConstraint{
		min: newV(2, 0, 0),
		max: newV(3, 0, 0),
	}
	uresult = unionConstraint{rc1, rc2}

	if actual = rc1.Union(rc2); !constraintEq(actual, uresult) {
		t.Errorf("Got constraint %q, but expected %q", actual, uresult)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, uresult) {
		t.Errorf("Got constraint %q, but expected %q", actual, uresult)
	}

	// Test disjoint at gt/lt boundary (non-adjacent)
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
	}
	rc2 = rangeConstraint{
		min: newV(2, 0, 0),
		max: newV(3, 0, 0),
	}
	uresult = unionConstraint{rc1, rc2}

	if actual = rc1.Union(rc2); !constraintEq(actual, uresult) {
		t.Errorf("Got constraint %q, but expected %q", actual, uresult)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, uresult) {
		t.Errorf("Got constraint %q, but expected %q", actual, uresult)
	}

	// Now, just have them touch at a single version
	rc1.includeMax = true
	rc2.includeMin = true
	result = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(3, 0, 0),
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// And top-adjacent at that version
	rc2.includeMin = false
	if actual = rc1.Union(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	// And bottom-adjacent at that version
	rc1.includeMax = false
	rc2.includeMin = true
	if actual = rc1.Union(rc2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}

	// Test excludes in overlapping range
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
		excl: []Version{
			newV(1, 6, 0),
		},
	}
	rc2 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(3, 0, 0),
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, rc2) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc2)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, rc2) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc2)
	}

	// Test excludes not in non-overlapping range
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
	}
	rc2 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(3, 0, 0),
		excl: []Version{
			newV(1, 1, 0),
		},
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, rc2) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc2)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, rc2) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc2)
	}

	// Ensure pure excludes come through as they should
	rc1 = rangeConstraint{
		min: Version{special: zeroVersion},
		max: Version{special: infiniteVersion},
		excl: []Version{
			newV(1, 6, 0),
		},
	}

	rc2 = rangeConstraint{
		min: Version{special: zeroVersion},
		max: Version{special: infiniteVersion},
		excl: []Version{
			newV(1, 6, 0),
			newV(1, 7, 0),
		},
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}

	rc1 = rangeConstraint{
		min: Version{special: zeroVersion},
		max: Version{special: infiniteVersion},
		excl: []Version{
			newV(1, 5, 0),
		},
	}

	if actual = rc1.Union(rc2); !constraintEq(actual, Any()) {
		t.Errorf("Got constraint %q, but expected %q", actual, Any())
	}
	if actual = rc2.Union(rc1); !constraintEq(actual, Any()) {
		t.Errorf("Got constraint %q, but expected %q", actual, Any())
	}

	// TODO test the pre-release special range stuff
}

func TestUnionIntersection(t *testing.T) {
	var actual Constraint
	// magic first
	u1 := unionConstraint{
		newV(1, 1, 0),
		newV(1, 2, 0),
		newV(1, 3, 0),
	}
	if actual = u1.Intersect(Any()); !constraintEq(actual, u1) {
		t.Errorf("Intersection of anything with Any should return self; got %s", actual)
	}
	if actual = u1.Intersect(None()); !IsNone(actual) {
		t.Errorf("Intersection of anything with None should always produce None; got %s", actual)
	}
	if u1.MatchesAny(None()) {
		t.Errorf("Can't match any when intersected with None")
	}

	// intersect of unions with single versions
	v1 := newV(1, 1, 0)
	if actual = u1.Intersect(v1); !constraintEq(actual, v1) {
		t.Errorf("Got constraint %q, but expected %q", actual, v1)
	}
	if actual = v1.Intersect(u1); !constraintEq(actual, v1) {
		t.Errorf("Got constraint %q, but expected %q", actual, v1)
	}

	// intersect of range with union of versions
	u1 = unionConstraint{
		newV(1, 1, 0),
		newV(1, 2, 0),
		newV(1, 3, 0),
	}
	rc1 := rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 0, 0),
	}

	if actual = u1.Intersect(rc1); !constraintEq(actual, u1) {
		t.Errorf("Got constraint %q, but expected %q", actual, u1)
	}
	if actual = rc1.Intersect(u1); !constraintEq(actual, u1) {
		t.Errorf("Got constraint %q, but expected %q", actual, u1)
	}

	u2 := unionConstraint{
		newV(1, 1, 0),
		newV(1, 2, 0),
	}

	if actual = u1.Intersect(u2); !constraintEq(actual, u2) {
		t.Errorf("Got constraint %q, but expected %q", actual, u2)
	}

	// Overlapping sub/supersets
	rc1 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(1, 6, 0),
	}
	rc2 := rangeConstraint{
		min: newV(2, 0, 0),
		max: newV(3, 0, 0),
	}
	rc3 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 0, 0),
	}
	rc4 := rangeConstraint{
		min: newV(2, 5, 0),
		max: newV(2, 6, 0),
	}
	u1 = unionConstraint{rc1, rc2}
	u2 = unionConstraint{rc3, rc4}
	ur := unionConstraint{rc1, rc4}

	if actual = u1.Intersect(u2); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}
	if actual = u2.Intersect(u1); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}

	// Ensure excludes carry as they should
	rc1.excl = []Version{newV(1, 5, 5)}
	u1 = unionConstraint{rc1, rc2}
	ur = unionConstraint{rc1, rc4}

	if actual = u1.Intersect(u2); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}
	if actual = u2.Intersect(u1); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}
}

func TestUnionUnion(t *testing.T) {
	var actual Constraint
	// magic first
	u1 := unionConstraint{
		newV(1, 1, 0),
		newV(1, 2, 0),
		newV(1, 3, 0),
	}
	if actual = u1.Union(Any()); !IsAny(actual) {
		t.Errorf("Union of anything with Any should always return Any; got %s", actual)
	}
	if actual = u1.Union(None()); !constraintEq(actual, u1) {
		t.Errorf("Union of anything with None should always return self; got %s", actual)
	}

	// union of uc with single versions
	// already present
	v1 := newV(1, 2, 0)
	if actual = u1.Union(v1); !constraintEq(actual, u1) {
		t.Errorf("Got constraint %q, but expected %q", actual, u1)
	}
	if actual = v1.Union(u1); !constraintEq(actual, u1) {
		t.Errorf("Got constraint %q, but expected %q", actual, u1)
	}

	// not present
	v2 := newV(1, 4, 0)
	ur := append(u1, v2)
	if actual = u1.Union(v2); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}
	if actual = v2.Union(u1); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}

	// union of uc with uc, all versions
	u2 := unionConstraint{
		newV(1, 3, 0),
		newV(1, 4, 0),
		newV(1, 5, 0),
	}
	ur = unionConstraint{
		newV(1, 1, 0),
		newV(1, 2, 0),
		newV(1, 3, 0),
		newV(1, 4, 0),
		newV(1, 5, 0),
	}

	if actual = u1.Union(u2); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}
	if actual = u2.Union(u1); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}

	// union that should compress versions into range
	rc1 := rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 0, 0),
	}

	if actual = u1.Union(rc1); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}
	if actual = rc1.Union(u1); !constraintEq(actual, rc1) {
		t.Errorf("Got constraint %q, but expected %q", actual, rc1)
	}

	rc1.max = newV(1, 4, 5)
	u3 := append(u2, newV(1, 7, 0))
	ur = unionConstraint{
		rc1,
		newV(1, 5, 0),
		newV(1, 7, 0),
	}

	if actual = u3.Union(rc1); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}
	if actual = rc1.Union(u3); !constraintEq(actual, ur) {
		t.Errorf("Got constraint %q, but expected %q", actual, ur)
	}
}

// Most version stuff got tested by range and/or union b/c most tests were
// repeated bidirectionally (set operations are commutative; testing in pairs
// helps us catch any situation where we fail to maintain that invariant)
func TestVersionSetOps(t *testing.T) {
	var actual Constraint

	v1 := newV(1, 0, 0)

	if actual = v1.Intersect(v1); !constraintEq(actual, v1) {
		t.Errorf("Version intersected with itself should be itself, got %q", actual)
	}
	if !v1.MatchesAny(v1) {
		t.Errorf("MatchesAny should work with a version against itself")
	}

	v2 := newV(2, 0, 0)
	if actual = v1.Intersect(v2); !IsNone(actual) {
		t.Errorf("Versions should only intersect with themselves, got %q", actual)
	}
	if v1.MatchesAny(v2) {
		t.Errorf("MatchesAny should not work when combined with anything other than itself")
	}

	result := unionConstraint{v1, v2}

	if actual = v1.Union(v1); !constraintEq(actual, v1) {
		t.Errorf("Version union with itself should return self, got %q", actual)
	}

	if actual = v1.Union(v2); !constraintEq(actual, result) {
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
	if actual = v1.Union(v2); !constraintEq(actual, result) {
		// Duplicate just to make sure ordering works right
		t.Errorf("Got constraint %q, but expected %q", actual, result)
	}
}

func TestAreAdjacent(t *testing.T) {
	rc1 := rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(2, 0, 0),
	}
	rc2 := rangeConstraint{
		min: newV(1, 2, 0),
		max: newV(2, 2, 0),
	}

	if areAdjacent(rc1, rc2) {
		t.Errorf("Ranges overlap, should not indicate as adjacent")
	}

	rc2 = rangeConstraint{
		min: newV(2, 0, 0),
	}

	if areAdjacent(rc1, rc2) {
		t.Errorf("Ranges are non-overlapping and non-adjacent, but reported as adjacent")
	}

	rc2.includeMin = true

	if !areAdjacent(rc1, rc2) {
		t.Errorf("Ranges are non-overlapping and adjacent, but reported as non-adjacent")
	}

	rc1.includeMax = true

	if areAdjacent(rc1, rc2) {
		t.Errorf("Ranges are overlapping at a single version, but reported as adjacent")
	}

	rc2.includeMin = false
	if !areAdjacent(rc1, rc2) {
		t.Errorf("Ranges are non-overlapping and adjacent, but reported as non-adjacent")
	}
}
