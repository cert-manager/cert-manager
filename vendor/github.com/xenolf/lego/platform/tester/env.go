package tester

import (
	"fmt"
	"os"
)

// EnvTest Environment variables manager for tests.
type EnvTest struct {
	keys   []string
	values map[string]string

	liveTestHook      func() bool
	liveTestExtraHook func() bool

	domain    string
	domainKey string
}

// NewEnvTest Creates an EnvTest.
func NewEnvTest(keys ...string) *EnvTest {
	values := make(map[string]string)
	for _, key := range keys {
		value := os.Getenv(key)
		if value != "" {
			values[key] = value
		}
	}

	return &EnvTest{
		keys:   keys,
		values: values,
	}
}

// WithDomain Defines the name of the environment variable used to define the domain related to the DNS request.
// If the domain is defined, it was considered mandatory to define a test as a "live" test.
func (e *EnvTest) WithDomain(key string) *EnvTest {
	e.domainKey = key
	e.domain = os.Getenv(key)
	return e
}

// WithLiveTestRequirements Defines the environment variables required to define a test as a "live" test.
// Replaces the default behavior (all keys are required).
func (e *EnvTest) WithLiveTestRequirements(keys ...string) *EnvTest {
	var countValuedVars int

	for _, key := range keys {
		if e.domainKey != key && !e.isManagedKey(key) {
			panic(fmt.Sprintf("Unauthorized action, the env var %s is not managed or it's not the key of the domain.", key))
		}

		if _, ok := e.values[key]; ok {
			countValuedVars++
		}
	}

	live := countValuedVars != 0 && len(keys) == countValuedVars

	e.liveTestHook = func() bool {
		return live
	}

	return e
}

// WithLiveTestExtra Allows to define an additional condition to flag a test as "live" test.
// This does not replace the default behavior.
func (e *EnvTest) WithLiveTestExtra(extra func() bool) *EnvTest {
	e.liveTestExtraHook = extra
	return e
}

// GetDomain Gets the domain value associated with the DNS challenge (linked to WithDomain method).
func (e *EnvTest) GetDomain() string {
	return e.domain
}

// IsLiveTest Checks whether environment variables allow running a "live" test.
func (e *EnvTest) IsLiveTest() bool {
	liveTest := e.liveTestExtra()

	if e.liveTestHook != nil {
		return liveTest && e.liveTestHook()
	}

	liveTest = liveTest && len(e.values) == len(e.keys)

	if liveTest && len(e.domainKey) > 0 && len(e.domain) == 0 {
		return false
	}

	return liveTest
}

// RestoreEnv Restores the environment variables to the initial state.
func (e *EnvTest) RestoreEnv() {
	for key, value := range e.values {
		os.Setenv(key, value)
	}
}

// ClearEnv Deletes all environment variables related to the test.
func (e *EnvTest) ClearEnv() {
	for _, key := range e.keys {
		os.Unsetenv(key)
	}
}

// GetValue Gets the stored value of an environment variable.
func (e *EnvTest) GetValue(key string) string {
	return e.values[key]
}

func (e *EnvTest) liveTestExtra() bool {
	if e.liveTestExtraHook == nil {
		return true
	}

	return e.liveTestExtraHook()
}

// Apply Sets/Unsets environment variables.
// Not related to the main environment variables.
func (e *EnvTest) Apply(envVars map[string]string) {
	for key, value := range envVars {
		if !e.isManagedKey(key) {
			panic(fmt.Sprintf("Unauthorized action, the env var %s is not managed.", key))
		}

		if len(value) == 0 {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, value)
		}
	}
}

func (e *EnvTest) isManagedKey(varName string) bool {
	for _, key := range e.keys {
		if key == varName {
			return true
		}
	}
	return false
}
