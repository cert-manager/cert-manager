package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/logging"
)

// LogError adds to the response writer the given error if it implements
// logging.ResponseLogger. If it does not implement it, then writes the error
// using the log package.
func LogError(rw http.ResponseWriter, err error) {
	if rl, ok := rw.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"error": err,
		})
	} else {
		log.Println(err)
	}
}

// JSON writes the passed value into the http.ResponseWriter.
func JSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		LogError(w, err)
	}
}

// ReadJSON reads JSON from the request body and stores it in the value
// pointed by v.
func ReadJSON(r io.Reader, v interface{}) error {
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return BadRequest(errors.Wrap(err, "error decoding json"))
	}
	return nil
}
