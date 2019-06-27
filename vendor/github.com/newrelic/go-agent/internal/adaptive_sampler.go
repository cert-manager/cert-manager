package internal

import (
	"math"
	"sync"
	"time"
)

// AdaptiveSampler calculates which transactions should be sampled.  An interface
// is used in the connect reply to facilitate testing.
type AdaptiveSampler interface {
	ComputeSampled(priority float32, now time.Time) bool
}

// SampleEverything is used for testing.
type SampleEverything struct{}

// SampleNothing is used when the application is not yet connected.
type SampleNothing struct{}

// ComputeSampled implements AdaptiveSampler.
func (s SampleEverything) ComputeSampled(priority float32, now time.Time) bool { return true }

// ComputeSampled implements AdaptiveSampler.
func (s SampleNothing) ComputeSampled(priority float32, now time.Time) bool { return false }

type adaptiveSampler struct {
	sync.Mutex
	period time.Duration
	target uint64

	// Transactions with priority higher than this are sampled.
	// This is 1 - sampleRatio.
	priorityMin float32

	currentPeriod struct {
		numSampled uint64
		numSeen    uint64
		end        time.Time
	}
}

// NewAdaptiveSampler creates an AdaptiveSampler.
func NewAdaptiveSampler(period time.Duration, target uint64, now time.Time) AdaptiveSampler {
	as := &adaptiveSampler{}
	as.period = period
	as.target = target
	as.currentPeriod.end = now.Add(period)

	// Sample the first transactions in the first period.
	as.priorityMin = 0.0
	return as
}

// ComputeSampled calculates if the transaction should be sampled.
func (as *adaptiveSampler) ComputeSampled(priority float32, now time.Time) bool {
	as.Lock()
	defer as.Unlock()

	// If the current time is after the end of the "currentPeriod".  This is in
	// a `for`/`while` loop in case there's a harvest where no sampling happened.
	// i.e. for situations where a single call to
	//    as.currentPeriod.end = as.currentPeriod.end.Add(as.period)
	// might not catch us up to the current period
	for now.After(as.currentPeriod.end) {
		as.priorityMin = 0.0
		if as.currentPeriod.numSeen > 0 {
			sampledRatio := float32(as.target) / float32(as.currentPeriod.numSeen)
			as.priorityMin = 1.0 - sampledRatio
		}
		as.currentPeriod.numSampled = 0
		as.currentPeriod.numSeen = 0
		as.currentPeriod.end = as.currentPeriod.end.Add(as.period)
	}

	as.currentPeriod.numSeen++

	// exponential backoff -- if the number of sampled items is greater than our
	// target, we need to apply the exponential backoff
	if as.currentPeriod.numSampled > as.target {
		if as.computeSampledBackoff(as.target, as.currentPeriod.numSeen, as.currentPeriod.numSampled) {
			as.currentPeriod.numSampled++
			return true
		}
		return false
	}

	if priority >= as.priorityMin {
		as.currentPeriod.numSampled++
		return true
	}

	return false
}

func (as *adaptiveSampler) computeSampledBackoff(target uint64, decidedCount uint64, sampledTrueCount uint64) bool {
	return float64(RandUint64N(decidedCount)) <
		math.Pow(float64(target), (float64(target)/float64(sampledTrueCount)))-math.Pow(float64(target), 0.5)
}
