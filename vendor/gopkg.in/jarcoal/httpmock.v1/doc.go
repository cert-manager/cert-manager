/*
HTTPmock provides tools for mocking HTTP responses.

Simple Example:
	func TestFetchArticles(t *testing.T) {
		httpmock.Activate()
		defer httpmock.DeactivateAndReset()

		httpmock.RegisterResponder("GET", "https://api.mybiz.com/articles.json",
			httpmock.NewStringResponder(200, `[{"id": 1, "name": "My Great Article"}]`))

		// do stuff that makes a request to articles.json
	}

Advanced Example:
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
				return resp
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

*/
package httpmock
