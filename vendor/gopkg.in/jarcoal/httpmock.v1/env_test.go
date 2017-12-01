package httpmock

import (
	"net/http"
	"os"
	"testing"
)

func TestEnv(t *testing.T) {
	DeactivateAndReset()

	orig := os.Getenv(envVarName)

	// put it in an enabled state
	if err := os.Setenv(envVarName, ""); err != nil {
		t.Fatal(err)
	} else if Disabled() {
		t.Fatal("expected not to be disabled")
	}

	// make sure an activation works
	Activate()
	if http.DefaultTransport != DefaultTransport {
		t.Fatal("expected http.DefaultTransport to be our DefaultTransport")
	}
	Deactivate()

	if err := os.Setenv(envVarName, "1"); err != nil {
		t.Fatal(err)
	} else if !Disabled() {
		t.Fatal("expected to be disabled")
	}

	// make sure activation doesn't work
	Activate()
	if http.DefaultTransport == DefaultTransport {
		t.Fatal("expected http.DefaultTransport to not be our DefaultTransport")
	}
	Deactivate()

	if err := os.Setenv(envVarName, orig); err != nil {
		t.Fatalf("could not reset %s to it's original value '%s'", envVarName, orig)
	}
}
