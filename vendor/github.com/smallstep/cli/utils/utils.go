package utils

import (
	"fmt"
	"os"
)

// Fail prints out the error struct if STEPDEBUG is true otherwise it just
// prints out the error message. Finally, it exits with an error code of 1.
func Fail(err error) {
	if err != nil {
		if os.Getenv("STEPDEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
