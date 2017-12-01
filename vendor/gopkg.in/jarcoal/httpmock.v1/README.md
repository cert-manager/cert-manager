# httpmock [![Build Status](https://travis-ci.org/jarcoal/httpmock.png?branch=master)](https://travis-ci.org/jarcoal/httpmock)

Easy mocking of http responses from external resources.

## Install

Uses gopkg to read from `v1` branch:

    go get gopkg.in/jarcoal/httpmock.v1

You can also use vendoring for the v1 branch if you feel so inclined.

Currently supports Go 1.7 but also works with 1.6 for now. 

### Simple Example:
```go
func TestFetchArticles(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://api.mybiz.com/articles.json",
		httpmock.NewStringResponder(200, `[{"id": 1, "name": "My Great Article"}]`))

  // get count info
  httpmock.GetTotalCallCount()

  // get the amount of calls for the registered responder
  info := httpmock.GetCallCountInfo()
  info["GET https://api.mybiz.com/articles.json"] // number of GET calls made to https://api.mybiz.com/articles.json

	// do stuff that makes a request to articles.json
}
```

### Advanced Example:
```go
func TestFetchArticles(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// our database of articles
	articles := make([]map[string]interface{}, 0)

	// mock to list out the articles
	httpmock.RegisterResponder("GET", "https://api.mybiz.com/articles.json",
		func(req *http.Request) (*http.Response, error) {
			resp, err := httpmock.NewJsonResponse(200, articles)
			if err != nil {
				return httpmock.NewStringResponse(500, ""), nil
			}
			return resp, nil
		},
	)

	// mock to add a new article
	httpmock.RegisterResponder("POST", "https://api.mybiz.com/articles.json",
		func(req *http.Request) (*http.Response, error) {
			article := make(map[string]interface{})
			if err := json.NewDecoder(req.Body).Decode(&article); err != nil {
				return httpmock.NewStringResponse(400, ""), nil
			}

			articles = append(articles, article)

			resp, err := httpmock.NewJsonResponse(200, article)
			if err != nil {
				return httpmock.NewStringResponse(500, ""), nil
			}
			return resp, nil
		},
	)

	// do stuff that adds and checks articles
}
```

### [Ginkgo](https://onsi.github.io/ginkgo/) Example:
```go
// article_suite_test.go

import (
	// ...
	"github.com/jarcoal/httpmock"
)
// ...
var _ = BeforeSuite(func() {
	// block all HTTP requests
	httpmock.Activate()
})

var _ = BeforeEach(func() {
	// remove any mocks
	httpmock.Reset()
})

var _ = AfterSuite(func() {
	httpmock.DeactivateAndReset()
})


// article_test.go

import (
	// ...
	"github.com/jarcoal/httpmock"
)

var _ = Describe("Articles", func() {
	It("returns a list of articles", func() {
		httpmock.RegisterResponder("GET", "https://api.mybiz.com/articles.json",
			httpmock.NewStringResponder(200, `[{"id": 1, "name": "My Great Article"}]`))

		// do stuff that makes a request to articles.json
	})
})
```
