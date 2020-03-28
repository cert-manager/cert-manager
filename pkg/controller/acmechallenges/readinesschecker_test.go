package acmechallenges

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

func TestDelayedAcceptReady(t *testing.T) {
	type input struct {
		currentTime   time.Time
		referenceTime time.Time
		delay         time.Duration
	}
	type output struct {
		delay           time.Duration
		conditionStatus cmmeta.ConditionStatus
	}
	type testCase struct {
		input
		output
	}
	now := time.Date(0, 0, 0, 0, 0, 0, 0, time.UTC)
	tests := map[string]testCase{
		"future": {
			input{
				currentTime:   now,
				referenceTime: now,
				delay:         time.Minute,
			},
			output{
				delay:           time.Minute,
				conditionStatus: cmmeta.ConditionFalse,
			},
		},
	}

	for title, tc := range tests {
		tc := tc
		t.Run(title, func(t *testing.T) {
			delay, condition := delayedAcceptReady(
				tc.input.currentTime,
				tc.input.referenceTime,
				tc.input.delay,
			)
			assert.Equal(t, tc.output.delay, delay)
			assert.Equal(t, tc.output.condition, condition)
		})
	}
}
