package sysinfo

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"runtime"
)

// BootID returns the boot ID of the executing kernel.
func BootID() (string, error) {
	if "linux" != runtime.GOOS {
		return "", ErrFeatureUnsupported
	}
	data, err := ioutil.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}

	return validateBootID(data)
}

type invalidBootID string

func (e invalidBootID) Error() string {
	return fmt.Sprintf("Boot id has unrecognized format, id=%q", string(e))
}

func isASCIIByte(b byte) bool {
	return (b >= 0x20 && b <= 0x7f)
}

func validateBootID(data []byte) (string, error) {
	// We're going to go for the permissive reading of
	// https://source.datanerd.us/agents/agent-specs/blob/master/Utilization.md:
	// any ASCII (excluding control characters, because I'm pretty sure that's not
	// in the spirit of the spec) string will be sent up to and including 128
	// bytes in length.
	trunc := bytes.TrimSpace(data)
	if len(trunc) > 128 {
		trunc = trunc[:128]
	}
	for _, b := range trunc {
		if !isASCIIByte(b) {
			return "", invalidBootID(data)
		}
	}

	return string(trunc), nil
}
