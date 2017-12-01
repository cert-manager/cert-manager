package httpmock

import (
	"os"
)

var envVarName = "GONOMOCKS"

func Disabled() bool {
	return os.Getenv(envVarName) != ""
}
