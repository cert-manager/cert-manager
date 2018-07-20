package dnsimple

import (
	"io"
	"net/http"
	"testing"
)

func TestAuthService_Whoami(t *testing.T) {
	setupMockServer()
	defer teardownMockServer()

	mux.HandleFunc("/v2/whoami", func(w http.ResponseWriter, r *http.Request) {
		httpResponse := httpResponseFixture(t, "/whoami/success.http")

		testMethod(t, r, "GET")
		testHeaders(t, r)

		w.WriteHeader(httpResponse.StatusCode)
		io.Copy(w, httpResponse.Body)
	})

	whoamiResponse, err := client.Identity.Whoami()
	if err != nil {
		t.Fatalf("Identity.Whoami() returned error: %v", err)
	}

	whoami := whoamiResponse.Data

	if whoami.User != nil {
		t.Fatalf("Identity.Whoami() returned not null user: `%v`", whoami.User)
	}

	if whoami.Account == nil {
		t.Fatalf("Identity.Whoami() returned null account")
	}

	account := whoami.Account

	if want, got := 1, account.ID; want != got {
		t.Fatalf("Identity.Whoami() returned ID expected to be `%v`, got `%v`", want, got)
	}

	if want, got := "example-account@example.com", account.Email; want != got {
		t.Fatalf("Identity.Whoami() returned Email expected to be `%v`, got `%v`", want, got)
	}

	if want, got := "dnsimple-professional", account.PlanIdentifier; want != got {
		t.Fatalf("Identity.Whoami() returned PlanIdentifier expected to be `%v`, got `%v`", want, got)
	}
}
