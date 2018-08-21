package semver

import "testing"

func init() {
	// disable constraint and version creation caching
	CacheConstraints = false
	CacheVersions = false
}

var (
	rc1 = rangeConstraint{
		min:        newV(1, 5, 0),
		max:        newV(2, 0, 0),
		includeMax: true,
	}
	rc2 = rangeConstraint{
		min: newV(2, 0, 0),
		max: newV(3, 0, 0),
	}
	rc3 = rangeConstraint{
		min: newV(1, 5, 0),
		max: newV(2, 0, 0),
	}
	rc4 = rangeConstraint{
		min: newV(1, 7, 0),
		max: newV(4, 0, 0),
	}
	rc5 = rangeConstraint{
		min: newV(2, 7, 0),
		max: newV(3, 0, 0),
	}
	rc6 = rangeConstraint{
		min: newV(3, 0, 1),
		max: newV(3, 0, 4),
	}
	rc7 = rangeConstraint{
		min: newV(1, 0, 0),
		max: newV(1, 2, 0),
	}
	// Two fully non-overlapping unions
	u1 = rc1.Union(rc7)
	u2 = rc5.Union(rc6)
)

/* Constraint creation benchmarks */

func benchNewConstraint(c string, b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewConstraint(c)
	}
}

func BenchmarkNewConstraintUnary(b *testing.B) {
	benchNewConstraint("=2.0", b)
}

func BenchmarkNewConstraintTilde(b *testing.B) {
	benchNewConstraint("~2.0.0", b)
}

func BenchmarkNewConstraintCaret(b *testing.B) {
	benchNewConstraint("^2.0.0", b)
}

func BenchmarkNewConstraintWildcard(b *testing.B) {
	benchNewConstraint("1.x", b)
}

func BenchmarkNewConstraintRange(b *testing.B) {
	benchNewConstraint(">=2.1.x, <3.1.0", b)
}

func BenchmarkNewConstraintUnion(b *testing.B) {
	benchNewConstraint("~2.0.0 || =3.1.0", b)
}

/* Validate benchmarks, including fails */

func benchValidateVersion(c, v string, b *testing.B) {
	version, _ := NewVersion(v)
	constraint, _ := NewConstraint(c)

	for i := 0; i < b.N; i++ {
		constraint.Matches(version)
	}
}

func BenchmarkValidateVersionUnary(b *testing.B) {
	benchValidateVersion("=2.0", "2.0.0", b)
}

func BenchmarkValidateVersionUnaryFail(b *testing.B) {
	benchValidateVersion("=2.0", "2.0.1", b)
}

func BenchmarkValidateVersionTilde(b *testing.B) {
	benchValidateVersion("~2.0.0", "2.0.5", b)
}

func BenchmarkValidateVersionTildeFail(b *testing.B) {
	benchValidateVersion("~2.0.0", "1.0.5", b)
}

func BenchmarkValidateVersionCaret(b *testing.B) {
	benchValidateVersion("^2.0.0", "2.1.0", b)
}

func BenchmarkValidateVersionCaretFail(b *testing.B) {
	benchValidateVersion("^2.0.0", "4.1.0", b)
}

func BenchmarkValidateVersionWildcard(b *testing.B) {
	benchValidateVersion("1.x", "1.4.0", b)
}

func BenchmarkValidateVersionWildcardFail(b *testing.B) {
	benchValidateVersion("1.x", "2.4.0", b)
}

func BenchmarkValidateVersionRange(b *testing.B) {
	benchValidateVersion(">=2.1.x, <3.1.0", "2.4.5", b)
}

func BenchmarkValidateVersionRangeFail(b *testing.B) {
	benchValidateVersion(">=2.1.x, <3.1.0", "1.4.5", b)
}

func BenchmarkValidateVersionUnion(b *testing.B) {
	benchValidateVersion("~2.0.0 || =3.1.0", "3.1.0", b)
}

func BenchmarkValidateVersionUnionFail(b *testing.B) {
	benchValidateVersion("~2.0.0 || =3.1.0", "3.1.1", b)
}

/* Version creation benchmarks */

func benchNewVersion(v string, b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewVersion(v)
	}
}

func BenchmarkNewVersionSimple(b *testing.B) {
	benchNewVersion("1.0.0", b)
}

func BenchmarkNewVersionPre(b *testing.B) {
	benchNewVersion("1.0.0-alpha", b)
}

func BenchmarkNewVersionMeta(b *testing.B) {
	benchNewVersion("1.0.0+metadata", b)
}

func BenchmarkNewVersionMetaDash(b *testing.B) {
	benchNewVersion("1.0.0+metadata-dash", b)
}

/* Union benchmarks */

func BenchmarkAdjacentRangeUnion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Union(rc1, rc2)
	}
}

func BenchmarkAdjacentRangeUnionMethod(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rc1.Union(rc2)
	}
}

func BenchmarkDisjointRangeUnion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Union(rc2, rc3)
	}
}

func BenchmarkDisjointRangeUnionMethod(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rc2.Union(rc3)
	}
}

func BenchmarkOverlappingRangeUnion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Union(rc1, rc4)
	}
}

func BenchmarkOverlappingRangeUnionMethod(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rc1.Union(rc4)
	}
}

func BenchmarkUnionUnion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Union(u1, u2)
	}
}

func BenchmarkUnionUnionMethod(b *testing.B) {
	for i := 0; i < b.N; i++ {
		u1.Union(u2)
	}
}

/* Intersection benchmarks */

func BenchmarkSubsetRangeIntersection(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Intersection(rc2, rc4)
	}
}

func BenchmarkSubsetRangeIntersectionMethod(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rc2.Intersect(rc4)
	}
}

func BenchmarkDisjointRangeIntersection(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Intersection(rc2, rc3)
	}
}

func BenchmarkDisjointRangeIntersectionMethod(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rc2.Intersect(rc3)
	}
}

func BenchmarkOverlappingRangeIntersection(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Intersection(rc1, rc4)
	}
}

func BenchmarkOverlappingRangeIntersectionMethod(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rc1.Intersect(rc4)
	}
}

func BenchmarkUnionIntersection(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Intersection(u1, u2)
	}
}

func BenchmarkUnionIntersectionMethod(b *testing.B) {
	for i := 0; i < b.N; i++ {
		u1.Intersect(u2)
	}
}
